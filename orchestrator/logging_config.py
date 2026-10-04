"""
Logging setup — text or JSON lines, with a per-request correlation id (Phase 5).

Log messages stay English (ADR-004: logs are read by developers and
machines). What this module adds is *shape*: with ORCHESTRATOR_LOG_FORMAT=json
every record is one JSON object per line so a log shipper (Loki, ELK,
CloudWatch, Datadog) can index it without a regex, and any `extra={...}`
fields a call site attaches (target_id, run_id, collector, ...) become
top-level keys.

A request id is bound to a contextvar by the API middleware for the duration
of each HTTP request and stamped on every record emitted while handling it,
so the lines produced by one call can be pulled together. Background
pipeline runs started by the scheduler have no request and log "-".

No third-party logging library: the formatter is ~40 lines and the
dependency would cost more than it returns at this size.
"""

from __future__ import annotations

import contextvars
import json
import logging
import sys
from datetime import UTC, datetime

from orchestrator.config import settings

# Bound by the API middleware; None outside a request.
request_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "request_id", default=None
)

TEXT_FORMAT = "%(asctime)s %(levelname)s %(name)s [%(request_id)s] %(message)s"

# Attributes every LogRecord carries; anything else in record.__dict__ was
# passed via `extra=` and is promoted to a top-level JSON key.
_RESERVED_ATTRS = frozenset(logging.LogRecord("", logging.INFO, "", 0, "", (), None).__dict__) | {
    "message",
    "asctime",
    "request_id",
    "taskName",
}

# Keys the JSON shape guarantees. An `extra=` field with one of these names is
# emitted under an `extra_` prefix rather than clobbering the real value — a
# log line whose "level" is not the log level would poison every dashboard
# built on it.
_STABLE_KEYS = frozenset({"ts", "level", "logger", "msg", "request_id", "exc", "stack"})


def current_request_id() -> str | None:
    """Return the request id bound to the current async context, if any."""
    return request_id_var.get()


class RequestIdFilter(logging.Filter):
    """Stamp record.request_id so the text format can print it."""

    def filter(self, record: logging.LogRecord) -> bool:
        """Attach the contextvar request id (or "-") to every record."""
        record.request_id = request_id_var.get() or "-"
        return True


class JsonFormatter(logging.Formatter):
    """One JSON object per line. Keys are stable; extras are added as-is."""

    def format(self, record: logging.LogRecord) -> str:
        """Serialise a record to one stable-keyed JSON line.

        The request id is read from the contextvar (never from ``extra=``) so
        a caller cannot forge correlation; ``extra`` fields colliding with
        stable keys are emitted under an ``extra_`` prefix.
        """
        ts = datetime.fromtimestamp(record.created, UTC)
        payload: dict[str, object] = {
            "ts": ts.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        # From the contextvar, never from the record: an `extra=` field named
        # request_id must not be able to forge the correlation id.
        request_id = request_id_var.get()
        if request_id:
            payload["request_id"] = request_id
        for key, value in record.__dict__.items():
            if key in _RESERVED_ATTRS or key.startswith("_"):
                continue
            if key in _STABLE_KEYS:
                key = f"extra_{key}"
            payload[key] = value
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        if record.stack_info:
            payload["stack"] = self.formatStack(record.stack_info)
        # default=str: a datetime or Path in `extra` must not take the log
        # line down with a TypeError.
        return json.dumps(payload, default=str, ensure_ascii=False)


def build_handler(log_format: str) -> logging.Handler:
    """Build the stdout handler for "text" or "json" log format."""
    handler = logging.StreamHandler(sys.stdout)
    if log_format == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter(TEXT_FORMAT))
    handler.addFilter(RequestIdFilter())
    return handler


def configure_logging(level: str | None = None, log_format: str | None = None) -> None:
    """
    Install a single root handler in the configured shape.

    Idempotent: replaces whatever handler a previous call (or uvicorn's
    defaults) installed. uvicorn's own loggers are routed through the root
    handler so access and error lines share the format — half-JSON output
    is worse than none.
    """
    level_name = (level or settings.orchestrator_log_level).strip().upper()
    fmt = (log_format or settings.orchestrator_log_format).strip().lower()

    numeric_level = logging.getLevelName(level_name)
    if not isinstance(numeric_level, int):
        # Invalid level: fall back to INFO rather than refuse to start. The
        # warning below is emitted with the handler already installed.
        numeric_level = logging.INFO
    if fmt not in {"text", "json"}:
        fmt = "text"

    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(build_handler(fmt))
    root.setLevel(numeric_level)

    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        uv_logger = logging.getLogger(name)
        for existing in list(uv_logger.handlers):
            uv_logger.removeHandler(existing)
        uv_logger.propagate = True

    if logging.getLevelName(level_name) != numeric_level:
        logging.getLogger(__name__).warning(
            "Unknown ORCHESTRATOR_LOG_LEVEL %r; using INFO",
            level or settings.orchestrator_log_level,
        )
    if (log_format or settings.orchestrator_log_format).strip().lower() != fmt:
        logging.getLogger(__name__).warning(
            "Unknown ORCHESTRATOR_LOG_FORMAT %r; using text",
            log_format or settings.orchestrator_log_format,
        )

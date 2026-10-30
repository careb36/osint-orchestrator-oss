"""No call site logs a field name that logging itself reserves.

`AGENTS.md` tells a contributor to put structured context in `extra={...}` and
not to name one `ts`, `level`, `logger`, `msg`, `request_id`, `exc` or `stack`.
The stated consequence — "yours is emitted as `extra_<name>` instead" — is only
true for five of the seven. Measured through the real call path:

===================  ========================================================
`extra={"level": …}`  becomes `extra_level`; a dashboard filtering on `level`
                      silently stops seeing this field
`extra={"msg": …}`    raises `KeyError` inside `Logger.makeRecord`, before any
                      formatter runs: the log call itself fails
`extra={"request_id"}`  is dropped with no key emitted at all
===================  ========================================================

The formatter cannot help with `msg` — Python rejects the name first — so the
only defence is not to write it. `test_logging_config.py` cannot catch it
either: its `_record()` helper sets attributes with `setattr`, which skips
`makeRecord`, so the crash path is never exercised there. That is the gap this
closes, on the source rather than on one hand-built record.

A `KeyError` in a log call is worse than it sounds: it lands inside whatever
except-block was being logged, so the line that explains a failure is replaced
by a `TypeError`/`KeyError` traceback about logging.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from orchestrator.logging_config import _RESERVED_ATTRS, _STABLE_KEYS

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "orchestrator"

# The `logging.Logger` methods that accept `extra=`. Scoping to these keeps
# pydantic's `ConfigDict(extra="forbid")` and `Observable(extra=...)` out: they
# are plain Name calls, not attribute calls on a logger.
_LOG_METHODS = frozenset(
    {"debug", "info", "warning", "warn", "error", "exception", "critical", "log"}
)


def _dict_keys(node: ast.expr, named: dict[str, ast.Dict]) -> set[str]:
    """Literal string keys of a dict expression, resolving `**name` spreads."""
    if isinstance(node, ast.Dict):
        keys: set[str] = set()
        for key, value in zip(node.keys, node.values, strict=True):
            if key is None:
                keys |= _dict_keys(value, named)
            elif isinstance(key, ast.Constant) and isinstance(key.value, str):
                keys.add(key.value)
        return keys
    if isinstance(node, ast.Name):
        return _dict_keys(named[node.id], named) if node.id in named else set()
    if isinstance(node, ast.IfExp):
        return _dict_keys(node.body, named) | _dict_keys(node.orelse, named)
    return set()


def _logging_extra_keys(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    # Context dicts are often built once and reused, sometimes passed
    # positionally to a helper that logs (collectors/_failure).
    named = {
        target.id: node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name) and isinstance(node.value, ast.Dict)
    }
    keys: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in _LOG_METHODS:
            continue
        for keyword in node.keywords:
            if keyword.arg == "extra":
                keys |= _dict_keys(keyword.value, named)
    # The same dicts, whether or not this file logs with them directly.
    for name, node in named.items():
        if name.endswith(("extra", "_ctx")):
            keys |= _dict_keys(node, named)
    return keys


def _all_extra_keys() -> dict[str, set[str]]:
    found = {path.name: _logging_extra_keys(path) for path in sorted(PACKAGE.rglob("*.py"))}
    keys = set().union(*found.values())
    # A rewrite that stops recognising the call sites would leave every check
    # below asserting over an empty set.
    assert len(keys) >= 20, (
        f"found only {len(keys)} logging extra keys under orchestrator/; the AST "
        "scan no longer recognises the call sites"
    )
    return found


def test_no_call_site_logs_a_key_the_formatter_would_rename() -> None:
    """`extra={"level": x}` comes out as `extra_level`, so a `level` filter misses it."""
    found = _all_extra_keys()
    offenders = {
        name: sorted(keys & (_STABLE_KEYS | _RESERVED_ATTRS))
        for name, keys in found.items()
        if keys & (_STABLE_KEYS | _RESERVED_ATTRS)
    }
    assert offenders == {}, (
        f"log call sites passing a reserved name in extra=: {offenders}. "
        "`ts`, `level`, `logger`, `exc` and `stack` are renamed to `extra_<name>`; "
        "`request_id` is dropped; `msg` and every other LogRecord attribute raise "
        "KeyError inside the log call. Pick a name of your own (see the established "
        "ones in AGENTS.md)."
    )


@pytest.mark.parametrize("name", sorted(_STABLE_KEYS))
def test_every_stable_key_really_is_reserved(name: str) -> None:
    """Each name must behave as documented — and the three behaviours differ.

    `AGENTS.md` says all seven are "emitted as `extra_<name>`". Measured, `msg`
    raises KeyError from `Logger.makeRecord` before any formatter runs, and
    `request_id` is skipped by the reserved check, so it is dropped rather than
    renamed. This pins which behaviour each name has, so the next reader cannot
    assume `msg` gets prefixed like `level`, and so the difference is a decision
    recorded in a test rather than a surprise.
    """
    import json
    import logging

    from orchestrator.logging_config import JsonFormatter

    logger = logging.getLogger("orchestrator.test.stable")
    try:
        logger.makeRecord("t", logging.INFO, "x.py", 1, "m", (), None, extra={name: "v"})
    except KeyError:
        # Python refuses the name outright: a real call site would crash here,
        # in the middle of whatever failure was being logged.
        assert name in _RESERVED_ATTRS, (
            f"{name!r} raises KeyError from Logger.makeRecord but is not in "
            "_RESERVED_ATTRS: the module's two lists disagree about it"
        )
        return

    record = logging.LogRecord("t", logging.INFO, "x.py", 1, "m", (), None)
    setattr(record, name, "v")
    payload = json.loads(JsonFormatter().format(record))
    if name in _RESERVED_ATTRS:
        # Skipped before the stable-prefix branch: no key reaches the line.
        assert name not in payload
        assert f"extra_{name}" not in payload
    else:
        assert payload[f"extra_{name}"] == "v"
        assert payload.get("level") == "INFO"


def test_text_format_carries_the_fields_the_operations_doc_promises() -> None:
    """`docs/operations.md` says text lines carry ts, level, logger, request id, msg.

    It used to say "only the message is printed", which was wrong: the format
    string has carried all five for as long as the module has. A placeholder the
    record cannot resolve would not raise — logging writes
    `KeyError: 'name'` into the line itself — so the assertions are on the
    rendered line, not on the format string.
    """
    import io
    import logging

    from orchestrator.logging_config import TEXT_FORMAT, build_handler

    handler = build_handler("text")
    stream = io.StringIO()
    handler.setStream(stream)
    logger = logging.getLogger("orchestrator.test.text")
    logger.handlers = [handler]
    logger.propagate = False
    logger.setLevel(logging.INFO)
    logger.info("collected %d", 3, extra={"target_id": "acme"})

    line = stream.getvalue().rstrip("\n")
    assert "INFO" in line  # level
    assert "orchestrator.test.text" in line  # logger name
    assert "[-]" in line  # request id, absent outside a request
    assert "collected 3" in line  # message, interpolated
    assert "acme" not in line  # structured fields are json-only
    # No placeholder was left unresolved by the filter.
    assert "KeyError" not in line
    for field in ("asctime", "levelname", "name", "request_id", "message"):
        assert f"%({field})s" in TEXT_FORMAT

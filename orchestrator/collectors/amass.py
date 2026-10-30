"""
Amass collector — OWASP Amass v5 subdomain enumeration.

Amass v5 is split into a long-running *engine* (an HTTP service that runs the
enumeration and persists everything it learns into an asset database) and thin
CLI clients that talk to it. We keep that split:

  - The engine runs as a sidecar container (docker-compose profile ``amass``,
    image ``owaspamass/amass``). Data-source credentials live in
    ``amass/datasources.yaml``, and in Amass v5 it is the *client* that loads
    them: ``oam_enum`` reads ``config.yaml`` (and, through
    ``options.datasources``, the credentials file) and posts the resulting
    session configuration to the engine. So the orchestrator container needs
    those files too, not just the engine.
  - This collector drives the engine with the two CLI clients copied into the
    orchestrator image from the same upstream image:
      1. ``oam_enum -engine <url> -d <fqdn> -dir <data_dir> ...`` submits the
         enumeration and blocks until the engine stops making progress.
      2. ``oam_subs -d <fqdn> -names -ip -dir <data_dir>`` reads the names the
         engine discovered (and the addresses they resolve to) straight from
         the SQLite asset database on the volume shared with the engine.

Why a shared volume instead of the engine's HTTP API for results: the v5 API
exposes session lifecycle and stats, not the discovered assets; ``oam_subs`` is
the supported way to read them back and its output format is stable
(``name[ ip1,ip2,...]`` per line).

STIX mapping (ADR-002: all STIX built in normalizer/stix.py):
  - Each discovered name → domain-name SCO (plus the target root itself).
  - Each address → ipv4-addr / ipv6-addr SCO.
  - relationship: domain-name → ip (resolves-to).
  - relationship: discovered domain-name → target root domain-name (related-to).

Failure policy (collector contract): never raises. Engine unreachable, CLI not
installed, non-zero exit or wall-clock timeout all return ``success=False``
with a sanitised error string, so the run is recorded PARTIAL/FAILED instead
of silently reporting zero findings.

Active mode (``collectors.amass.active``) attempts zone transfers and
certificate grabs against the target's own infrastructure. It is off by
default and should stay off unless the target's ``authorization`` covers
active probing.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
import re
import uuid
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import httpx
import yaml

from orchestrator.collectors import BaseCollector
from orchestrator.config import settings
from orchestrator.models import (
    CollectorName,
    CollectorResult,
    Observable,
    Relationship,
    Target,
)

logger = logging.getLogger(__name__)

_HEALTH_TIMEOUT_SECONDS = 10
# Bytes of subprocess diagnostics (stderr / enum log) kept in an error string.
_DIAGNOSTIC_TAIL_CHARS = 500

# One DNS label: letters, digits, hyphen (not leading/trailing) and underscore
# (service labels such as ``_dmarc`` are legitimate enumeration output).
_LABEL_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")


class AmassError(RuntimeError):
    """A CLI client failed; the message is safe to surface to operators."""


def _datasources_ready(config: Path) -> bool:
    """True when the client can load ``config`` without failing on a missing file.

    ``oam_enum`` resolves ``options.datasources`` relative to the config file's
    own directory and aborts when the file is absent. Credentials are optional,
    so a config that names a file nobody created must fall back to the
    unauthenticated run rather than break enumeration.
    """
    try:
        data = yaml.safe_load(config.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError):
        return False
    if data is None:  # empty file: nothing to resolve, nothing to fail on
        data = {}
    if not isinstance(data, dict):
        return False
    options = data.get("options") or {}
    if not isinstance(options, dict):
        return False
    relative = options.get("datasources")
    if not isinstance(relative, str) or not relative:
        return True
    return (config.parent / relative).resolve().is_file()


def _strip_url_userinfo(url: str) -> str:
    """Return URL with userinfo removed, preserving scheme/host/port/path/query."""
    parsed = urlsplit(url)
    if not parsed.username and not parsed.password:
        return url
    host = parsed.hostname or ""
    if parsed.port is not None:
        host = f"{host}:{parsed.port}"
    return urlunsplit((parsed.scheme, host, parsed.path, parsed.query, parsed.fragment))


def _sanitize_error_text(text: str) -> str:
    """Remove userinfo from any http(s) URLs embedded in an error string."""
    return re.sub(r"(https?://)([^/\s@]+)@", r"\1", text)


def _tail(text: str, limit: int = _DIAGNOSTIC_TAIL_CHARS) -> str:
    """Last ``limit`` characters of ``text`` on one line, for error strings."""
    collapsed = " ".join(text.split())
    if len(collapsed) <= limit:
        return collapsed
    return "…" + collapsed[-limit:]


def _is_hostname(name: str) -> bool:
    if not name or len(name) > 253:
        return False
    return all(_LABEL_RE.match(label) for label in name.split("."))


def _in_scope(name: str, root: str) -> bool:
    return name == root or name.endswith("." + root)


def parse_subs_output(text: str, root: str) -> tuple[dict[str, list[str]], int]:
    """
    Parse ``oam_subs -names -ip`` output.

    Each line is ``name`` optionally followed by a space and a comma-separated
    list of addresses. Returns an ordered ``{name: [addresses]}`` map (names
    lower-cased, trailing dots stripped, addresses normalised and de-duplicated,
    in-scope names only) and the number of lines or tokens skipped as garbage.
    """
    root = root.lower().rstrip(".")
    names: dict[str, list[str]] = {}
    skipped = 0
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        head, _, rest = line.partition(" ")
        name = head.lower().rstrip(".")
        if not _is_hostname(name) or not _in_scope(name, root):
            skipped += 1
            continue
        addresses = names.setdefault(name, [])
        for token in rest.split(","):
            token = token.strip()
            if not token:
                continue
            try:
                address = str(ipaddress.ip_address(token))
            except ValueError:
                skipped += 1
                continue
            if address not in addresses:
                addresses.append(address)
    return names, skipped


def _address_type(address: str) -> str:
    return "ipv6-addr" if ipaddress.ip_address(address).version == 6 else "ipv4-addr"


class AmassCollector(BaseCollector):
    """
    Collector that runs an OWASP Amass v5 enumeration for the target's root
    domain through the engine sidecar and reads the results back with
    ``oam_subs``.

    Disabled by default (``collectors.amass.enabled: false`` in CollectorSet).
    """

    name = CollectorName.AMASS

    def __init__(self, target: Target) -> None:
        super().__init__(target)
        self._engine_url = settings.amass_engine_url.rstrip("/")
        self._data_dir = settings.amass_data_dir
        self._enum_bin = settings.amass_enum_bin
        self._subs_bin = settings.amass_subs_bin
        self._config_file = Path(settings.amass_config_file)

    # ─── Command lines ────────────────────────────────────────────────────────

    def enum_argv(self, log_name: str) -> list[str]:
        """Build the ``oam_enum`` command line; ``log_name`` is relative to ``-dir``."""
        cfg = self.target.collectors.amass
        argv = [
            self._enum_bin,
            "-engine",
            self._engine_url,
            "-d",
            self.target.fqdn,
            "-dir",
            self._data_dir,
            "-timeout",
            str(cfg.progress_timeout_minutes),
            "-log",
            log_name,
            "-silent",
            "-nocolor",
        ]
        if cfg.active:
            argv.append("-active")
        if cfg.brute:
            argv.append("-brute")
        if cfg.include:
            argv.extend(["-include", ",".join(cfg.include)])
        if cfg.exclude:
            argv.extend(["-exclude", ",".join(cfg.exclude)])
        argv.extend(self.config_argv())
        return argv

    def config_argv(self) -> list[str]:
        """``-config`` when a usable configuration file is mounted here."""
        if not _datasources_ready(self._config_file):
            return []
        return ["-config", str(self._config_file)]

    def subs_argv(self) -> list[str]:
        """Build the ``oam_subs`` command line that reads the results back."""
        # No ``-silent`` here: it would also discard the names on stdout.
        return [
            self._subs_bin,
            "-d",
            self.target.fqdn,
            "-names",
            "-ip",
            "-dir",
            self._data_dir,
            "-nocolor",
        ]

    # ─── Collection ───────────────────────────────────────────────────────────

    async def collect(self) -> CollectorResult:
        """Run enum + subs for the target; degrade to ``success=False`` on any failure."""
        cfg = self.target.collectors.amass
        fqdn = self.target.fqdn
        safe_engine = _strip_url_userinfo(self._engine_url)
        if self.config_argv():
            logger.info(
                "Amass: loading data-source credentials from %s",
                self._config_file,
                extra={"collector": "amass"},
            )
        else:
            logger.info(
                "Amass: no usable configuration at %s; running without data-source credentials",
                self._config_file,
                extra={"collector": "amass"},
            )
        stage = "health"
        try:
            async with asyncio.timeout(cfg.timeout_seconds):
                if not await self._engine_healthy():
                    return self._failure(f"Amass engine unreachable at {safe_engine}")
                stage = "enum"
                await self._run_enum()
                stage = "subs"
                output = await self._run(self.subs_argv())
        except TimeoutError:
            logger.error(
                "Amass timed out after %ss during %s for %s", cfg.timeout_seconds, stage, fqdn
            )
            return self._failure(f"Amass timed out after {cfg.timeout_seconds}s (during {stage})")
        except AmassError as exc:
            logger.error("Amass %s failed for %s: %s", stage, fqdn, exc)
            return self._failure(str(exc))
        except Exception as exc:  # noqa: BLE001 — contract: never raise
            logger.error("Amass collector error for %s during %s: %s", fqdn, stage, exc)
            return self._failure(f"Amass {stage} failed: {exc}")

        names, skipped = parse_subs_output(output, fqdn)
        return self._build_result(names, skipped)

    async def _engine_healthy(self) -> bool:
        url = f"{self._engine_url}/api/v1/health"
        try:
            async with httpx.AsyncClient(timeout=_HEALTH_TIMEOUT_SECONDS) as client:
                response = await client.get(url)
        except httpx.HTTPError as exc:
            logger.warning("Amass engine health check failed: %s", _sanitize_error_text(str(exc)))
            return False
        if response.is_success:
            return True
        logger.warning("Amass engine health check returned HTTP %s", response.status_code)
        return False

    async def _run_enum(self) -> None:
        # ``-silent`` also discards stderr, so ask oam_enum to write its
        # diagnostics (engine log stream included) to a file we can tail.
        # oam_enum resolves ``-log`` relative to ``-dir`` (and would otherwise
        # leave a session-<token>.log behind on every run), so the name is
        # relative and the file is removed once the run is over.
        log_name = f"oam_enum-{self.target.id}-{uuid.uuid4().hex}.log"
        log_path = Path(self._data_dir) / log_name
        try:
            await self._run(self.enum_argv(log_name))
        except AmassError as exc:
            detail = _read_tail(log_path)
            raise AmassError(f"{exc} — {detail}" if detail else str(exc)) from None
        finally:
            with contextlib.suppress(OSError):
                log_path.unlink()

    async def _run(self, argv: list[str]) -> str:
        """Run a CLI client to completion; return stdout, raise AmassError on failure."""
        binary = argv[0]
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            raise AmassError(
                f"{binary} is not installed in this image "
                "(set AMASS_ENUM_BIN / AMASS_SUBS_BIN or rebuild the orchestrator image)"
            ) from None
        try:
            stdout, stderr = await proc.communicate()
        except BaseException:
            # Wall-clock timeout (CancelledError) or shutdown: never leave a
            # detached enumeration running against the engine.
            if proc.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
                with contextlib.suppress(Exception):
                    await proc.wait()
            raise
        if proc.returncode != 0:
            detail = _tail(_sanitize_error_text(stderr.decode(errors="replace")))
            message = f"{Path(binary).name} exited {proc.returncode}"
            raise AmassError(f"{message}: {detail}" if detail else message)
        return stdout.decode(errors="replace")

    # ─── Result assembly ──────────────────────────────────────────────────────

    def _build_result(self, names: dict[str, list[str]], skipped: int) -> CollectorResult:
        cfg = self.target.collectors.amass
        root = self.target.fqdn.lower().rstrip(".")
        observables: list[Observable] = [Observable(type="domain-name", value=root)]
        relationships: list[Relationship] = []
        seen_domains = {root}
        seen_addresses: set[str] = set()

        for name, addresses in names.items():
            if name not in seen_domains:
                seen_domains.add(name)
                observables.append(Observable(type="domain-name", value=name))
                relationships.append(
                    Relationship(
                        source_value=name,
                        source_type="domain-name",
                        target_value=root,
                        target_type="domain-name",
                        relationship_type="related-to",
                    )
                )
            for address in addresses:
                address_type = _address_type(address)
                if address not in seen_addresses:
                    seen_addresses.add(address)
                    observables.append(Observable(type=address_type, value=address))
                relationships.append(
                    Relationship(
                        source_value=name,
                        source_type="domain-name",
                        target_value=address,
                        target_type=address_type,
                        relationship_type="resolves-to",
                    )
                )

        mode = "active" if cfg.active else "passive"
        if cfg.brute:
            mode += "+brute"
        notes = [
            f"amass: {mode} enumeration discovered {len(seen_domains) - 1} names "
            f"and {len(seen_addresses)} addresses under {root}"
        ]
        if skipped:
            notes.append(f"amass: skipped {skipped} unparseable or out-of-scope output lines")
        logger.info(
            "Amass (%s) found %d names / %d addresses for %s",
            mode,
            len(seen_domains) - 1,
            len(seen_addresses),
            root,
        )
        return CollectorResult(
            collector=self.name,
            target_fqdn=self.target.fqdn,
            observables=observables,
            relationships=relationships,
            notes=notes,
        )

    def _failure(self, error: str) -> CollectorResult:
        return CollectorResult(
            collector=self.name,
            target_fqdn=self.target.fqdn,
            success=False,
            error=_sanitize_error_text(error),
        )


def _read_tail(path: Path) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return _tail(_sanitize_error_text(text))

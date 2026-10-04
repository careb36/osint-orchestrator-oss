"""
SocialOSINT collector — Phase 4b.

Talks to a running OWASP SocialOSINT web service
(https://github.com/bm-github/owasp-social-osint-agent) via its REST API.
The web service performs LLM-powered OSINT on configured social accounts and
returns a markdown analysis report.

Integration decision (see docs/socialosint.md):
  The agent ships both a CLI (--stdin) and a FastAPI web server (/api/v1/).
  We use the HTTP interface because it:
    - Decouples credentials from the orchestrator container (platform tokens
      live only in the socialosint service environment).
    - Avoids subprocess management and stdin/stdout marshalling.
    - Surfaces platform availability cleanly via GET /api/v1/platforms.
  The trade-off is that the service must be running (docker-compose profile
  "socialosint") before the collector executes. The collector returns
  success=False gracefully if the service is unreachable.

STIX mapping (ADR-002: all STIX built in normalizer/stix.py):
  - Each (platform, username) input pair → user-account SCO.
    user_id = "platform:handle" (lowercased) so that the same handle on two
    different platforms produces two distinct, deterministic STIX objects.
    account_type stays "generic" (it is an ID-contributing property); the
    platform travels as the x_platform custom property.
  - A profile URL constructed from platform + handle → url SCO.
  - relationship: user-account → url (related-to).
  - relationship: user-account → domain-name of target (related-to).
  - The LLM analysis report → CollectorResult.notes (not facts, not observables).
    Labelled "análisis de SocialOSINT, no verificado".
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from orchestrator.collectors import BaseCollector
from orchestrator.config import settings
from orchestrator.i18n import resolve_language
from orchestrator.models import (
    SUPPORTED_PLATFORMS,
    CollectorName,
    CollectorResult,
    Observable,
    Relationship,
)

logger = logging.getLogger(__name__)

# Supported platforms and their profile URL templates.
# {handle} is substituted with the (already-lowercased) username.
# Mastodon handles may be "user@instance.tld"; if so the URL is derived from
# the instance part; otherwise no URL is emitted (account observable still is).
_PROFILE_URLS: dict[str, str] = {
    "twitter": "https://twitter.com/{handle}",
    "reddit": "https://reddit.com/u/{handle}",
    "github": "https://github.com/{handle}",
    "bluesky": "https://bsky.app/profile/{handle}",
    "hackernews": "https://news.ycombinator.com/user?id={handle}",
    # mastodon is handled separately (instance-dependent)
}

_POLL_INTERVAL_SECONDS = 5


def _osint_query(lang: str) -> str:
    """
    Build the analysis query for SocialOSINT in the target's configured language.

    The SocialOSINT LLM uses this prompt to structure its report, so the response
    language follows the same per-target language convention as the rest of the
    orchestrator (ADR-004).
    """
    return (
        "Summarise the public activity and interests of these accounts. "
        "Identify any notable technical topics, projects, or associations. "
        f"Flag anything of potential security or threat-intelligence relevance. "
        f"Respond in {lang}."
    )


def _mastodon_url(handle: str) -> str | None:
    """Return a profile URL for a Mastodon handle of the form user@instance.tld."""
    if "@" in handle:
        user, instance = handle.split("@", 1)
        return f"https://{instance}/@{user}"
    return None


def _profile_url(platform: str, handle: str) -> str | None:
    """Construct a profile URL for the given platform and handle, or None."""
    if platform == "mastodon":
        return _mastodon_url(handle)
    template = _PROFILE_URLS.get(platform)
    if template is None:
        return None
    return template.format(handle=handle)


def _parse_available_platforms(data: Any) -> set[str]:
    """
    Parse the response from GET /api/v1/platforms.

    The endpoint returns either a plain list of strings or a dict with a
    'platforms' key (exact schema depends on service version). Accept both.
    """
    if isinstance(data, list):
        return {str(p).lower() for p in data if isinstance(p, str)}
    if isinstance(data, dict):
        # Common shapes: {"platforms": [...]} or {"available": [...]}
        for key in ("platforms", "available", "configured"):
            val = data.get(key)
            if isinstance(val, list):
                return {str(p).lower() for p in val if isinstance(p, str)}
    return set()


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


class SocialOSINTCollector(BaseCollector):
    """
    Collector that queries the OWASP SocialOSINT web service for social-media
    account OSINT on a list of handles associated with a target.

    Disabled by default (collectors.socialosint.enabled: false in CollectorSet).
    Only runs when:
      - enabled: true in the target config
      - At least one username is configured
      - At least one requested platform has credentials in the service
    """

    name = CollectorName.SOCIALOSINT

    async def collect(self) -> CollectorResult:
        """Run the SocialOSINT analysis for the target's configured handles.

        Degrades instead of raising: an unreachable/timing-out service returns
        ``success=False`` with an error string, as do missing usernames,
        platforms, or service credentials.
        """
        cfg = self.target.collectors.socialosint

        usernames = [username.strip() for username in cfg.usernames if username.strip()]
        platforms = [platform.lower().strip() for platform in cfg.platforms if platform.strip()]

        if not usernames:
            error = "SocialOSINT: no usernames configured"
            logger.warning("%s for target %s", error, self.target.fqdn)
            return CollectorResult(
                collector=self.name,
                target_fqdn=self.target.fqdn,
                success=False,
                error=error,
            )

        base_url = settings.socialosint_url
        safe_base_url = _strip_url_userinfo(base_url)
        # Per-target timeout_seconds overrides the global SOCIALOSINT_TIMEOUT_SECONDS;
        # CollectorConfig.timeout_seconds defaults to settings.socialosint_timeout_seconds.
        timeout = float(cfg.timeout_seconds)
        request_timeout = max(1.0, min(timeout, 20.0))

        unknown_platforms = sorted(
            {platform for platform in platforms if platform not in SUPPORTED_PLATFORMS}
        )
        if unknown_platforms:
            error = (
                "SocialOSINT: unsupported platform(s): "
                f"{', '.join(unknown_platforms)}. Supported platforms: "
                f"{', '.join(sorted(SUPPORTED_PLATFORMS))}."
            )
            logger.warning("%s target=%s", error, self.target.fqdn)
            return CollectorResult(
                collector=self.name,
                target_fqdn=self.target.fqdn,
                success=False,
                error=error,
            )

        if not platforms:
            error = "SocialOSINT: no platforms configured"
            logger.warning("%s for target %s", error, self.target.fqdn)
            return CollectorResult(
                collector=self.name,
                target_fqdn=self.target.fqdn,
                success=False,
                error=error,
            )

        try:
            async with httpx.AsyncClient(base_url=base_url, timeout=request_timeout) as client:
                session_ref: dict[str, str | None] = {"id": None}
                try:
                    async with asyncio.timeout(timeout):
                        return await self._run(client, usernames, platforms, session_ref)
                finally:
                    if session_ref["id"]:
                        await self._delete_session(client, session_ref["id"])
        except TimeoutError:
            logger.warning(
                "SocialOSINT: wall-clock timeout after %.0fs at %s", timeout, safe_base_url
            )
            return CollectorResult(
                collector=self.name,
                target_fqdn=self.target.fqdn,
                success=False,
                error=f"SocialOSINT service timeout after {timeout:.0f}s",
            )
        except httpx.TimeoutException:
            logger.warning("SocialOSINT: request timeout reaching %s", safe_base_url)
            return CollectorResult(
                collector=self.name,
                target_fqdn=self.target.fqdn,
                success=False,
                error=(
                    "SocialOSINT request timeout: an HTTP call exceeded "
                    f"the per-request limit ({request_timeout:.0f}s)"
                ),
            )
        except httpx.ConnectError:
            logger.warning("SocialOSINT: cannot reach service at %s", safe_base_url)
            return CollectorResult(
                collector=self.name,
                target_fqdn=self.target.fqdn,
                success=False,
                error=f"SocialOSINT service unreachable at {safe_base_url}",
            )
        except Exception as exc:  # noqa: BLE001
            sanitized_error = _sanitize_error_text(str(exc))
            logger.error(
                "SocialOSINT: unexpected error for target %s at %s: %s",
                self.target.fqdn,
                safe_base_url,
                sanitized_error,
            )
            return CollectorResult(
                collector=self.name,
                target_fqdn=self.target.fqdn,
                success=False,
                error=sanitized_error,
            )

    async def _run(
        self,
        client: httpx.AsyncClient,
        usernames: list[str],
        platforms: list[str],
        session_ref: dict[str, str | None],
    ) -> CollectorResult:
        """Execute the service workflow: platforms → session → analyse → poll → export."""
        # 1. Which platforms are actually configured in the service?
        available = await self._get_available_platforms(client)

        effective_platforms: dict[str, list[str]] = {}
        skipped: list[str] = []
        for platform in platforms:
            if platform.lower() in available:
                effective_platforms[platform.lower()] = [u.lower() for u in usernames]
            else:
                skipped.append(platform)

        if skipped:
            logger.warning(
                "SocialOSINT: platforms %s not configured (missing credentials) — skipped",
                ", ".join(skipped),
            )

        if not effective_platforms:
            error = "SocialOSINT: no requested platform has configured credentials in the service"
            logger.warning("%s target=%s", error, self.target.fqdn)
            return CollectorResult(
                collector=self.name,
                target_fqdn=self.target.fqdn,
                success=False,
                error=error,
            )

        # 2. Create a session and start analysis
        lang = resolve_language(self.target.language)
        session_id = await self._create_session(client, effective_platforms)
        session_ref["id"] = session_id
        job_id = await self._start_analysis(client, session_id, lang)

        # 3. Poll until complete (or timeout from outer collect() context)
        await self._wait_for_job(client, job_id)

        # 4. Fetch the report
        report_text = await self._get_report(client, session_id)

        # 5. Build CollectorResult from (platform, username) inputs + report
        return self._build_result(effective_platforms, report_text, skipped)

    async def _get_available_platforms(self, client: httpx.AsyncClient) -> set[str]:
        """Return the lowercased platform names the service has credentials for."""
        try:
            resp = await client.get("/api/v1/platforms")
            resp.raise_for_status()
            return _parse_available_platforms(resp.json())
        except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPStatusError):
            raise  # propagate: TimeoutError/ConnectError → collect() network handler;
            # HTTPStatusError → collect()'s broad except → success=False (service broken,
            # not "no credentials")
        except Exception as exc:  # noqa: BLE001
            # JSON parse errors or other unexpected failures also propagate as broken service
            raise RuntimeError(
                f"SocialOSINT: unexpected response from /api/v1/platforms: {exc}"
            ) from exc

    async def _create_session(
        self,
        client: httpx.AsyncClient,
        platforms: dict[str, list[str]],
    ) -> str:
        """Create an analysis session for the platform→handles map; return its id."""
        payload = {
            "name": f"osint-orchestrator:{self.target.fqdn}",
            "platforms": platforms,
        }
        resp = await client.post("/api/v1/sessions", json=payload)
        resp.raise_for_status()
        return str(resp.json()["id"])

    async def _start_analysis(self, client: httpx.AsyncClient, session_id: str, lang: str) -> str:
        """Kick off the LLM analysis job for a session; return the job id."""
        resp = await client.post(
            f"/api/v1/sessions/{session_id}/analyse",
            json={"query": _osint_query(lang)},
        )
        resp.raise_for_status()
        return str(resp.json()["job_id"])

    async def _wait_for_job(
        self,
        client: httpx.AsyncClient,
        job_id: str,
    ) -> None:
        """Poll every five seconds until completion or the outer wall-clock timeout."""
        while True:
            resp = await client.get(f"/api/v1/jobs/{job_id}")
            resp.raise_for_status()
            data = resp.json()
            status = str(data.get("status", "")).lower()
            if status in ("complete", "completed", "done"):
                return
            if status in ("error", "failed"):
                raise RuntimeError(f"SocialOSINT job {job_id} failed: {data.get('message', '')}")
            await asyncio.sleep(_POLL_INTERVAL_SECONDS)

    async def _delete_session(self, client: httpx.AsyncClient, session_id: str) -> None:
        try:
            resp = await client.delete(f"/api/v1/sessions/{session_id}")
            # Treat 404 as already cleaned up by upstream.
            if resp.status_code in (200, 202, 204, 404):
                return
            resp.raise_for_status()
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "SocialOSINT: failed to delete session %s for target %s: %s",
                session_id,
                self.target.fqdn,
                _sanitize_error_text(str(exc)),
            )

    async def _get_report(self, client: httpx.AsyncClient, session_id: str) -> str:
        """Export the session and return the most recent query's Markdown report."""
        resp = await client.get(f"/api/v1/sessions/{session_id}/export")
        resp.raise_for_status()
        export = resp.json()
        # The export contains the session object. Queries are stored under
        # session["queries"] as a list; we take the most recent query's report.
        session = export if "queries" in export else export.get("session", export)
        queries = session.get("queries", [])
        if queries:
            last = queries[-1]
            return str(last.get("report", ""))
        return ""

    def _build_result(
        self,
        platforms: dict[str, list[str]],
        report_text: str,
        skipped_platforms: list[str] | None = None,
    ) -> CollectorResult:
        """Map inputs to observables/relationships and attach the report as a note.

        One ``user-account`` per (platform, handle) with ``user_id`` =
        "platform:handle", its profile ``url`` when constructable, and
        relationships account→url and account→target domain. The LLM report
        goes to ``notes`` labelled unverified — never to observables.
        """
        observables: list[Observable] = []
        relationships: list[Relationship] = []
        notes: list[str] = []

        # The normaliser resolves relationship endpoints only against the
        # observables in this result, so the target domain must be emitted
        # here or every user-account → domain-name edge is silently dropped.
        target_domain = self.target.fqdn
        observables.append(Observable(type="domain-name", value=target_domain))

        for platform, handles in platforms.items():
            for handle in handles:
                handle_lower = handle.lower()
                # user_id = "platform:handle" so the same handle on two different
                # platforms (e.g. "alice" on GitHub and on Bluesky) produces two
                # distinct UserAccount observables with different STIX ids.
                # The platform is passed as context only; the normaliser keeps
                # account_type="generic" because it is an ID-contributing
                # property and must match every other producer.
                account_value = f"{platform}:{handle_lower}"

                observables.append(
                    Observable(
                        type="user-account",
                        value=account_value,
                        extra={"platform": platform},
                    )
                )

                # Profile URL (if constructable for this platform)
                url = _profile_url(platform, handle_lower)
                if url:
                    observables.append(Observable(type="url", value=url))
                    # user-account → url
                    relationships.append(
                        Relationship(
                            source_type="user-account",
                            source_value=account_value,
                            target_type="url",
                            target_value=url,
                            relationship_type="related-to",
                        )
                    )

                # user-account → target domain
                relationships.append(
                    Relationship(
                        source_type="user-account",
                        source_value=account_value,
                        target_type="domain-name",
                        target_value=target_domain,
                        relationship_type="related-to",
                    )
                )

        # LLM analysis → note (not a fact)
        if report_text and report_text.strip():
            notes.append(f"[análisis de SocialOSINT, no verificado]\n\n{report_text.strip()}")

        if skipped_platforms:
            notes.append(
                f"Plataformas omitidas por falta de credenciales: {', '.join(skipped_platforms)}"
            )

        return CollectorResult(
            collector=self.name,
            target_fqdn=self.target.fqdn,
            observables=observables,
            relationships=relationships,
            notes=notes,
            success=True,
        )

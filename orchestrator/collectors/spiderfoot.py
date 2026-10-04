"""
SpiderFoot collector.

SpiderFoot exposes a CherryPy web UI + unofficial REST endpoints at port 5001.
There is NO versioned /api/v1/ prefix — all endpoints are at root path.

Key endpoints used (shapes checked against SpiderFoot 4.0 sfwebui.py):
  POST /startscan   → with ``Accept: application/json``: ["SUCCESS", "<scan id>"]
                      or ["ERROR", "<message>"]; without that header it
                      answers 303 to the HTML scan page
  GET  /scanstatus?id=<id>  → [name, target, created, started, ended, status, risk]
  GET  /scaneventresults?id=<id>&eventType=  → rows of
                      [last_seen, data, source_data, module, ..., event_type]
                      with data/source HTML-escaped and the type last
  GET  /ping        → health check

Reference: smicallef/spiderfoot:sfwebui.py (port 5001, @cherrypy.expose methods)
"""

from __future__ import annotations

import asyncio
import html
import logging
import uuid
from datetime import UTC, datetime

import httpx

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

# SpiderFoot event types → STIX observable type
_SF_EVENT_TO_STIX: dict[str, str] = {
    "IP_ADDRESS": "ipv4-addr",
    "IPV6_ADDRESS": "ipv6-addr",
    "INTERNET_NAME": "domain-name",
    "DOMAIN_NAME": "domain-name",
    "DOMAIN_NAME_PARENT": "domain-name",
    "URL_ADVERT": "url",
    "EMAILADDR": "email-addr",
    "EMAILADDR_COMPROMISED": "email-addr",
    "URL_STATIC": "url",
    "URL_DYNAMIC": "url",
    "SSL_CERTIFICATE_ISSUED": "x509-certificate",
    "NETBLOCK_OWNER": "autonomous-system",
    "BGP_AS_OWNER": "autonomous-system",
}

# Which SF event types create a "resolves-to" relationship with the target domain
_RESOLVES_FROM_DOMAIN = {"IP_ADDRESS", "IPV6_ADDRESS", "INTERNET_NAME"}


class SpiderFootCollector(BaseCollector):
    """HTTP collector driving a running SpiderFoot service (start → poll → parse).

    This is the only collector performing live DNS/TLS/HTTP probing of the
    target — see the Authorised-use policy. Modules come from the target
    config, falling back to ``SPIDERFOOT_MODULES``; the whole scan is bounded
    by ``timeout_seconds``.
    """

    name = CollectorName.SPIDERFOOT

    def __init__(self, target: Target) -> None:
        super().__init__(target)
        self._base_url = settings.spiderfoot_url
        cfg = target.collectors.spiderfoot
        self._timeout = cfg.timeout_seconds
        self._modules = cfg.modules or settings.spiderfoot_modules.split(",")

    async def collect(self) -> CollectorResult:
        """Start a scan, wait for completion and map raw events to observables.

        Never raises: any failure (service down, timeout, parse error) returns
        ``success=False`` so one collector cannot take the run down.
        """
        fqdn = self.target.fqdn
        logger.info("SpiderFoot: starting scan for %s", fqdn)

        async with httpx.AsyncClient(base_url=self._base_url, timeout=30) as client:
            try:
                scan_id = await self._start_scan(client, fqdn)
                logger.info("SpiderFoot scan %s started for %s", scan_id, fqdn)
                await self._wait_for_scan(client, scan_id)
                raw_events = await self._fetch_results(client, scan_id)
                return self._parse(raw_events, fqdn)
            except Exception as exc:  # noqa: BLE001
                logger.error("SpiderFoot failed for %s: %s", fqdn, exc)
                return CollectorResult(
                    collector=self.name,
                    target_fqdn=fqdn,
                    success=False,
                    error=str(exc),
                )

    # ── Internal ──────────────────────────────────────────────────────────────

    async def _start_scan(self, client: httpx.AsyncClient, fqdn: str) -> str:
        """POST /startscan and return the scan ID."""
        scan_name = f"orchestrator-{fqdn}-{uuid.uuid4().hex[:8]}"
        modules = ",".join(self._modules)

        resp = await client.post(
            "/startscan",
            # Without this header SpiderFoot answers 303 to the HTML scan page.
            headers={"Accept": "application/json"},
            data={
                "scanname": scan_name,
                "scantarget": fqdn,
                "modulelist": modules,
                "typelist": "",
                "usecase": "all",
            },
        )
        resp.raise_for_status()
        data = resp.json()
        # SpiderFoot 4 returns ["SUCCESS", "<id>"] or ["ERROR", "<message>"];
        # a dict with an id is accepted for other builds.
        if isinstance(data, dict):
            scan_id = data.get("id") or data.get("scanId") or data.get("scan_id")
            if scan_id:
                return str(scan_id)
        if isinstance(data, list) and len(data) >= 2:
            if data[0] == "SUCCESS" and data[1]:
                return str(data[1])
            if data[0] == "ERROR":
                raise RuntimeError(f"SpiderFoot refused the scan: {data[1]}")
        raise ValueError(f"Unexpected /startscan response: {data}")

    async def _wait_for_scan(self, client: httpx.AsyncClient, scan_id: str) -> None:
        """Poll /scanstatus until FINISHED, ERROR, or timeout."""
        deadline = asyncio.get_event_loop().time() + self._timeout
        poll_interval = 10

        while asyncio.get_event_loop().time() < deadline:
            await asyncio.sleep(poll_interval)
            resp = await client.get("/scanstatus", params={"id": scan_id})
            resp.raise_for_status()
            data = resp.json()
            # /scanstatus returns [name, target, created, started, ended, status, risk]
            # (or a dict on other builds)
            status = self._extract_status(data)
            logger.debug("SpiderFoot scan %s status: %s", scan_id, status)
            if status in ("FINISHED", "ABORT-REQUESTED", "ABORTED"):
                return
            if status == "ERROR-FAILED":
                raise RuntimeError(f"SpiderFoot scan {scan_id} failed with ERROR-FAILED")

        raise TimeoutError(f"SpiderFoot scan {scan_id} did not finish within {self._timeout}s")

    @staticmethod
    def _extract_status(data: list | dict) -> str:
        """Normalise the scan status out of SpiderFoot's dict-or-rows response."""
        if isinstance(data, dict):
            return data.get("status", "UNKNOWN")
        if isinstance(data, list) and len(data) >= 6 and isinstance(data[5], str):
            return data[5]
        return "UNKNOWN"

    async def _fetch_results(self, client: httpx.AsyncClient, scan_id: str) -> list[dict]:
        """GET /scaneventresults and return list of event rows."""
        resp = await client.get(
            "/scaneventresults",
            params={"id": scan_id, "eventType": ""},
            timeout=60,
        )
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, list):
            return data
        return []

    def _parse(self, events: list[dict | list], fqdn: str) -> CollectorResult:
        """
        Convert SpiderFoot event rows to CollectorResult.

        SpiderFoot 4 /scaneventresults returns rows like:
          [last_seen, data, source_data, module, confidence, visibility, risk,
           hash, false_positive, ..., event_type]
        with ``data`` HTML-escaped and the event type in the last column, or
        dicts with "type", "data", etc. on other builds.
        """
        observables: list[Observable] = []
        relationships: list[Relationship] = []
        seen_values: set[str] = set()

        # Always include the root target
        observables.append(Observable(type="domain-name", value=fqdn))
        seen_values.add(fqdn)

        for event in events:
            if isinstance(event, list) and len(event) >= 11:
                event_type = str(event[-1])
                data = html.unescape(str(event[1]))
            elif isinstance(event, dict):
                event_type = event.get("type", "")
                data = event.get("data", "")
            else:
                continue

            if not data or data in seen_values:
                continue

            stix_type = _SF_EVENT_TO_STIX.get(event_type)
            if stix_type:
                seen_values.add(data)
                obs = Observable(type=stix_type, value=data, extra={"sf_event": event_type})
                observables.append(obs)

                if event_type in _RESOLVES_FROM_DOMAIN:
                    relationships.append(
                        Relationship(
                            source_value=fqdn,
                            source_type="domain-name",
                            target_value=data,
                            target_type=stix_type,
                            relationship_type="resolves-to",
                        )
                    )

        return CollectorResult(
            collector=self.name,
            target_fqdn=fqdn,
            collected_at=datetime.now(UTC),
            observables=observables,
            relationships=relationships,
            success=True,
        )

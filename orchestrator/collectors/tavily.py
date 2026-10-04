"""
Tavily collector — opt-in web research for authorised targets.

The collector asks a small, fixed set of due-diligence questions about the
target's domain through the Tavily Search API and turns the answers into
``url`` observables plus one note per result. It is off unless a target sets
``collectors.tavily.enabled: true`` and ``TAVILY_API_KEY`` is configured.

Bounds, all enforced here rather than trusted to the provider:

- ``max_calls_per_run`` (per target, clamped by ``TAVILY_MAX_CALLS_PER_RUN``)
  caps the number of search requests.
- ``max_results`` (per target, clamped by ``TAVILY_MAX_RESULTS``) caps the
  results requested and kept per query.
- ``timeout_seconds`` is the wall-clock budget for the whole collector run,
  retries and backoff included; each request gets the remaining budget.
- Retries happen only on 429, 5xx and transport errors, with exponential
  backoff. Any other 4xx (bad key, bad payload) fails the query at once.

Failure policy (collector contract): never raises. Every failure is returned
as ``CollectorResult(success=False, error=...)``.
"""

from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import Awaitable, Callable, Iterable
from typing import Any
from urllib.parse import urlsplit

import httpx

from orchestrator.collectors import BaseCollector
from orchestrator.config import settings
from orchestrator.i18n import resolve_language
from orchestrator.models import CollectorName, CollectorResult, Observable
from orchestrator.textsafe import flatten_untrusted

logger = logging.getLogger(__name__)

TAVILY_SEARCH_URL = "https://api.tavily.com/search"

# Three templates per language so the default ``max_calls_per_run`` (3) covers
# the whole set; raising the cap does not change coverage.
# The target is a plain quoted search term, not a ``site:`` scope: adverse
# news, sanctions and litigation are reported by third parties, not on the
# entity's own domain. ``include_domains`` exists for operators who want to
# restrict the sources.
_QUERY_TEMPLATES: dict[str, list[str]] = {
    "en": [
        '"{target}" adverse news OR sanctions OR litigation OR regulatory action',
        '"{target}" ownership structure shareholders ultimate beneficial owner',
        '"{target}" legal proceedings court case settlement investigation',
    ],
    "es": [
        '"{target}" noticias adversas OR sanciones OR litigios OR acciones regulatorias',
        '"{target}" estructura societaria accionistas beneficiario final',
        '"{target}" procesos judiciales demanda acuerdo investigación',
    ],
}

_RETRIES = 3
_ALLOWED_SCHEMES = frozenset({"http", "https"})
_LABEL_RE = re.compile(r"\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def split_csv(value: str | Iterable[str]) -> list[str]:
    """Normalise a comma-separated setting (or an already-split list) to a clean list."""
    parts = value.split(",") if isinstance(value, str) else list(value)
    return [part.strip() for part in parts if part and part.strip()]


def is_hostname(name: str) -> bool:
    """True for a plausible DNS name: dotted labels, letters/digits/hyphens only."""
    name = name.lower().rstrip(".")
    if not name or "." not in name or len(name) > 253:
        return False
    return all(_LABEL_RE.match(label) for label in name.split("."))


def _is_retryable_status(status_code: int) -> bool:
    return status_code == 429 or status_code >= 500


class TavilyCollector(BaseCollector):
    """Web-search collector built around the Tavily API. Disabled by default."""

    name = CollectorName.TAVILY

    async def collect(self) -> CollectorResult:
        cfg = self.target.collectors.tavily
        fqdn = self.target.fqdn.strip()
        log_extra = {"target_id": self.target.id, "collector": self.name.value}

        if not cfg.enabled:
            return self._failure(fqdn, "Tavily: collector disabled", log_extra)
        if not settings.tavily_api_key:
            return self._failure(fqdn, "Tavily: API key not configured", log_extra)
        if not self.target.authorization or not self.target.purpose:
            return self._failure(
                fqdn, "Tavily: target authorization and purpose are required", log_extra
            )
        if not is_hostname(fqdn):
            return self._failure(fqdn, "Tavily: target must be a domain name", log_extra)

        max_calls = min(cfg.max_calls_per_run, settings.tavily_max_calls_per_run)
        if max_calls <= 0:
            return self._failure(
                fqdn, "Tavily: call budget is 0 (TAVILY_MAX_CALLS_PER_RUN)", log_extra
            )
        max_results = max(1, min(cfg.max_results, settings.tavily_max_results))
        queries = self.build_queries(fqdn)[:max_calls]
        budget = float(cfg.timeout_seconds)
        deadline = asyncio.get_running_loop().time() + budget

        results: list[dict[str, Any]] = []
        notes: list[str] = []
        failures: list[str] = []
        seen_urls: set[str] = set()
        timed_out = False
        try:
            async with asyncio.timeout(budget):
                for query in queries:
                    data = await self._search(query, cfg, max_results, deadline)
                    if data is None:
                        failures.append(query)
                        continue
                    items = [item for item in data.get("results") or [] if isinstance(item, dict)]
                    for item in items[:max_results]:
                        # One observable and one note per distinct URL: the
                        # same page answering two queries must not produce two
                        # STIX Notes with different ids.
                        url = self._safe_url(item.get("url"))
                        if url is None or url in seen_urls:
                            continue
                        seen_urls.add(url)
                        results.append(item)
                        note = self._note_from_result(item)
                        if note:
                            notes.append(note)
                    if cfg.include_answer and data.get("answer"):
                        answer = flatten_untrusted(str(data["answer"]))[:500]
                        notes.append(
                            f"tavily | answer | query={flatten_untrusted(query)} | {answer}"
                        )
        except TimeoutError:
            timed_out = True

        if timed_out:
            logger.warning(
                "Tavily timed out after %ss for %s", cfg.timeout_seconds, fqdn, extra=log_extra
            )
            return CollectorResult(
                collector=self.name,
                target_fqdn=fqdn,
                success=False,
                error=f"Tavily: timed out after {cfg.timeout_seconds}s",
                observables=self._to_observables(results),
                notes=notes,
            )

        if failures and len(failures) == len(queries):
            logger.warning(
                "Tavily: all %d queries failed for %s",
                len(queries),
                fqdn,
                extra={**log_extra, "failed_queries": len(failures)},
            )
            return CollectorResult(
                collector=self.name,
                target_fqdn=fqdn,
                success=False,
                error=f"Tavily: all {len(queries)} queries failed; see the collector log",
                observables=[],
                notes=notes,
            )
        if failures:
            notes.append(f"tavily: {len(failures)} of {len(queries)} queries failed")

        if not results:
            notes.append("tavily: no public results matched the query set")

        return CollectorResult(
            collector=self.name,
            target_fqdn=fqdn,
            observables=self._to_observables(results),
            notes=notes,
            success=True,
        )

    # ─── Queries ──────────────────────────────────────────────────────────────

    def build_queries(self, fqdn: str) -> list[str]:
        """Query set in the target's language (per-target override, then global)."""
        language = resolve_language(self.target.language)
        templates = _QUERY_TEMPLATES.get(language, _QUERY_TEMPLATES["en"])
        return [template.format(target=fqdn) for template in templates]

    # ─── HTTP ─────────────────────────────────────────────────────────────────

    async def _search(
        self, query: str, cfg, max_results: int, deadline: float
    ) -> dict[str, Any] | None:
        payload = {
            "query": query,
            "search_depth": cfg.search_depth or settings.tavily_search_depth,
            "max_results": max_results,
            "include_domains": split_csv(cfg.include_domains)
            or split_csv(settings.tavily_include_domains),
            "exclude_domains": split_csv(cfg.exclude_domains)
            or split_csv(settings.tavily_exclude_domains),
            "include_answer": bool(cfg.include_answer),
            "include_raw_content": False,
        }
        headers = {"Authorization": f"Bearer {settings.tavily_api_key}"}

        async def _request() -> dict[str, Any]:
            remaining = max(1.0, deadline - asyncio.get_running_loop().time())
            async with httpx.AsyncClient(timeout=remaining) as client:
                response = await client.post(TAVILY_SEARCH_URL, headers=headers, json=payload)
                response.raise_for_status()
                data = response.json()
                return data if isinstance(data, dict) else {}

        try:
            return await self._with_retry(_request, query)
        except (httpx.HTTPError, ValueError) as exc:
            status_code = (
                exc.response.status_code if isinstance(exc, httpx.HTTPStatusError) else None
            )
            logger.warning(
                "Tavily search failed for %s (status=%s): %s",
                self.target.fqdn,
                status_code,
                exc,
                extra={
                    "target_id": self.target.id,
                    "collector": self.name.value,
                    "status_code": status_code,
                    "query": query,
                },
            )
            return None

    async def _with_retry(
        self, request: Callable[[], Awaitable[dict[str, Any]]], query: str
    ) -> dict[str, Any]:
        """Retry on 429, 5xx and transport errors only; other errors propagate at once."""
        for attempt in range(_RETRIES + 1):
            status_code: int | None = None
            try:
                return await request()
            except httpx.HTTPStatusError as exc:
                status_code = exc.response.status_code
                if attempt >= _RETRIES or not _is_retryable_status(status_code):
                    raise
            except httpx.TransportError:
                if attempt >= _RETRIES:
                    raise
            delay = float(2**attempt)
            logger.warning(
                "Tavily request failed (status=%s), retrying in %.0fs (attempt %d/%d)",
                status_code,
                delay,
                attempt + 1,
                _RETRIES,
                extra={
                    "target_id": self.target.id,
                    "collector": self.name.value,
                    "status_code": status_code,
                    "query": query,
                },
            )
            await asyncio.sleep(delay)
        raise RuntimeError("unreachable")  # pragma: no cover

    # ─── Result assembly ──────────────────────────────────────────────────────

    @staticmethod
    def _safe_url(value: Any) -> str | None:
        url = str(value or "").strip()
        if not url:
            return None
        parts = urlsplit(url)
        if parts.scheme.lower() not in _ALLOWED_SCHEMES or not parts.netloc:
            return None
        return url

    @classmethod
    def _note_from_result(cls, item: dict[str, Any]) -> str | None:
        # Only fields that are stable across re-crawls go into the note: the
        # normaliser derives the STIX Note id from this text, so a relevance
        # score or a content digest would create a new Note on every run.
        url = cls._safe_url(item.get("url"))
        if url is None:
            return None
        title = flatten_untrusted(str(item.get("title") or "")) or "result"
        snippet = flatten_untrusted(str(item.get("content") or item.get("snippet") or ""))
        published = item.get("published_date") or item.get("publishedAt") or "unknown"
        bits = ["tavily", title, f"url={url}", f"published={flatten_untrusted(str(published))}"]
        if snippet:
            bits.append(f"snippet={snippet[:200]}")
        return " | ".join(bits)

    @classmethod
    def _to_observables(cls, results: Iterable[dict[str, Any]]) -> list[Observable]:
        observables: list[Observable] = []
        seen: set[str] = set()
        for item in results:
            url = cls._safe_url(item.get("url")) if isinstance(item, dict) else None
            if url is None or url in seen:
                continue
            seen.add(url)
            observables.append(Observable(type="url", value=url, extra={"source": "tavily"}))
        return observables

    def _failure(self, fqdn: str, error: str, log_extra: dict[str, Any]) -> CollectorResult:
        logger.warning("%s target=%s", error, fqdn, extra=log_extra)
        return CollectorResult(collector=self.name, target_fqdn=fqdn, success=False, error=error)

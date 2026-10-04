"""Tavily collector — OPT-IN web research for authorised targets.

This collector uses the Tavily Search API to ask brief, accountable research
questions against a monitored target. It never raises: every failure is mapped to
``CollectorResult(success=False, error=...)`` so a bad API key or a transient 429
leaves the run partial instead of crashing the entire pipeline.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from collections.abc import Iterable
from typing import Any

import httpx

from orchestrator.collectors import BaseCollector
from orchestrator.config import settings
from orchestrator.models import CollectorName, CollectorResult, Observable

logger = logging.getLogger(__name__)

_QUERY_TEMPLATES = {
    "en": [
        "site:{target} adverse news OR sanctions OR litigation OR regulatory action",
        "site:{target} corporate structure ownership beneficial owners published shareholders",
        "site:{target} legal proceedings court case settlement investigation",
        "site:{target} final beneficiary owner ultimate beneficial owner published ownership hierarchy",
    ],
    "es": [
        "site:{target} noticias adversas OR sanciones OR litigios OR acciones regulatorias",
        "site:{target} estructura societaria propiedad beneficiarios finales accionistas publicados",
        "site:{target} procesos judiciales demanda acuerdo investigación",
        "site:{target} beneficiario final propietario real estructura societaria publicada",
    ],
}


class TavilyCollector(BaseCollector):
    """Web-search collector built around the Tavily API. Disabled by default."""

    name = CollectorName.TAVILY

    async def collect(self) -> CollectorResult:
        cfg = self.target.collectors.tavily
        target = self.target.fqdn.strip()

        if not settings.tavily_api_key:
            error = "Tavily: API key not configured"
            logger.warning("%s target=%s", error, target)
            return self._failure(target, error)

        if not self.target.authorization or not self.target.purpose:
            error = "Tavily: target authorization and purpose are required"
            logger.warning("%s target=%s", error, target)
            return self._failure(target, error)

        if not target or not self._is_target_allowed(target):
            error = "Tavily: target must be a domain or explicitly allowed entity"
            logger.warning("%s target=%s", error, target)
            return self._failure(target, error)

        if not cfg.enabled:
            return CollectorResult(
                collector=self.name,
                target_fqdn=target,
                success=False,
                error="Tavily: collector disabled",
            )

        queries = self._build_queries(target)
        max_calls = max(1, cfg.max_calls_per_run)
        results: list[dict[str, Any]] = []
        notes: list[str] = []

        for _idx, query in enumerate(queries[:max_calls]):
            query_result = await self._search(query, cfg)
            results.extend(query_result)
            if not query_result:
                continue
            for item in query_result[: cfg.max_results]:
                note = self._note_from_result(item)
                if note:
                    notes.append(note)

        if not results:
            notes.append("tavily: no public results matched the query set")

        observables = self._to_observables(results)
        return CollectorResult(
            collector=self.name,
            target_fqdn=target,
            observables=observables,
            notes=notes,
            success=True,
        )

    @staticmethod
    def _is_target_allowed(target: str) -> bool:
        """Reject obvious person-centric searches unless the operator explicitly opts in."""
        return "." in target

    def _build_queries(self, target: str) -> list[str]:
        language = "en" if self.target.language in {"en", None} else "es"
        templates = _QUERY_TEMPLATES.get(language, _QUERY_TEMPLATES["en"])
        return [template.format(target=target) for template in templates]

    async def _search(self, query: str, cfg) -> list[dict[str, Any]]:
        payload = {
            "query": query,
            "search_depth": cfg.search_depth or settings.tavily_search_depth,
            "max_results": max(1, min(cfg.max_results, settings.tavily_max_results)),
            "include_domains": list(cfg.include_domains or settings.tavily_include_domains),
            "exclude_domains": list(cfg.exclude_domains or settings.tavily_exclude_domains),
            "include_answer": bool(cfg.include_answer),
            "include_raw_content": True,
        }

        async def _request() -> dict[str, Any]:
            headers = {"Authorization": "Bearer " + settings.tavily_api_key}
            async with httpx.AsyncClient(
                timeout=float(cfg.timeout_seconds or settings.tavily_timeout_seconds)
            ) as client:
                response = await client.post(
                    "https://api.tavily.com/search",
                    headers=headers,
                    json=payload,
                )
                if response.status_code == 429:
                    raise httpx.HTTPStatusError(
                        "rate limited",
                        request=response.request,
                        response=response,
                    )
                response.raise_for_status()
                return response.json()

        try:
            data = await self._with_retry(_request)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Tavily search failed for %s query=%r: %s", self.target.fqdn, query, exc)
            return []
        results = data.get("results") if isinstance(data, dict) else []
        return [item for item in results if isinstance(item, dict)]

    async def _with_retry(self, request_callable, *, retries: int = 3):
        last_exc: Exception | None = None
        for attempt in range(retries + 1):
            try:
                return await request_callable()
            except httpx.HTTPStatusError as exc:
                if (
                    exc.response is not None
                    and exc.response.status_code == 429
                    and attempt < retries
                ):
                    delay = (2**attempt) * 1.0
                    logger.warning(
                        "Tavily 429, retrying in %.1fs (attempt=%d/%d)", delay, attempt + 1, retries
                    )
                    await asyncio.sleep(delay)
                    last_exc = exc
                    continue
                raise
            except httpx.HTTPError as exc:
                if attempt < retries:
                    await asyncio.sleep((2**attempt) * 1.0)
                    last_exc = exc
                    continue
                raise
        if last_exc is not None:
            raise last_exc
        raise RuntimeError("Tavily request failed")

    @staticmethod
    def _note_from_result(item: dict[str, Any]) -> str | None:
        url = str(item.get("url") or "").strip()
        if not url:
            return None
        title = str(item.get("title") or "").strip()
        snippet = str(item.get("content") or item.get("snippet") or "").strip()
        score = item.get("score")
        published = item.get("published_date") or item.get("publishedAt")
        raw = item.get("raw_content") or snippet
        digest = hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest() if raw else ""
        bits = [
            "tavily",
            title or "result",
            f"url={url}",
            f"published={published or 'unknown'}",
            f"score={score if score is not None else 'n/a'}",
        ]
        if digest:
            bits.append(f"sha256={digest}")
        if snippet:
            bits.append(f"snippet={snippet[:200]}")
        return " | ".join(bits)

    @staticmethod
    def _to_observables(results: Iterable[dict[str, Any]]) -> list[Observable]:
        observables: list[Observable] = []
        seen: set[tuple[str, str]] = set()
        for item in results:
            if not isinstance(item, dict):
                continue
            url = str(item.get("url") or "").strip()
            if not url:
                continue
            key = ("url", url)
            if key in seen:
                continue
            seen.add(key)
            observables.append(Observable(type="url", value=url, extra={"source": "tavily"}))
        return observables

    def _failure(self, fqdn: str, error: str) -> CollectorResult:
        return CollectorResult(
            collector=self.name,
            target_fqdn=fqdn,
            success=False,
            error=error,
        )

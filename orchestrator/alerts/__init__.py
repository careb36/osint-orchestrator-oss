"""
Alert dispatch for OSINT Orchestrator (Phase 4a).

Supported channels:
  - WebhookNotifier  — POST JSON to ALERT_WEBHOOK_URL with HMAC-SHA256 signature.
  - EmailNotifier    — SMTP with optional STARTTLS.

Usage::

    from orchestrator.alerts import build_notifiers, AlertEvent
    notifiers = build_notifiers()
    for n in notifiers:
        await n.send(event)

Channels without configuration are skipped with a single warning at startup
(logged once, not once per run).
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import smtplib
import ssl
from abc import ABC, abstractmethod
from datetime import datetime
from email.mime.text import MIMEText

import httpx
from pydantic import BaseModel

from orchestrator.config import settings
from orchestrator.i18n import resolve_language, t, tv
from orchestrator.models import AlertCaseReason, AlertsConfig, RunStatus

logger = logging.getLogger(__name__)

# ─── Event schema ─────────────────────────────────────────────────────────────


class AlertObservable(BaseModel):
    """A single observable included in an alert payload."""

    stix_type: str
    value: str
    stix_id: str


class AlertEvent(BaseModel):
    """
    Canonical alert payload.  Serialised to JSON for the webhook body and
    rendered as plain text for the email body.

    This is the public webhook contract — document any field change in the
    docs/operations.md under "Alerts".
    """

    target_id: str
    target_fqdn: str
    run_id: int
    run_status: str
    risk_level: str  # low | medium | high | critical | unknown
    # New observables from get_run_delta; empty when include_values=False (only
    # the count in new_observable_count is populated in that case).
    new_observables: list[AlertObservable]
    # Total count of new observables for this run.
    new_observable_count: int
    report_path: str | None
    finding_summary: str | None
    generated_at: datetime


# ─── Notifier protocol ────────────────────────────────────────────────────────


class Notifier(ABC):
    """Abstract base for alert channels."""

    channel: str

    @abstractmethod
    async def send(self, event: AlertEvent) -> None:
        """Send the event.  Raises on failure."""


# ─── Webhook ─────────────────────────────────────────────────────────────────


_WEBHOOK_NO_SECRET_LOGGED = False


def _hmac_signature(secret: str, body: bytes) -> str:
    """HMAC-SHA256 of the exact JSON body, formatted for X-Orchestrator-Signature."""
    sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={sig}"


class WebhookNotifier(Notifier):
    """
    POST the AlertEvent as JSON to ALERT_WEBHOOK_URL.

    Headers:
      Content-Type: application/json
      X-Orchestrator-Signature: sha256=<HMAC-SHA256 of body with ALERT_WEBHOOK_SECRET>
        (omitted with a one-time warning when ALERT_WEBHOOK_SECRET is empty)

    Retry policy: none here. ``send`` makes exactly one POST and raises on
    any failure. Retries are owned by the persistent alert delivery queue
    (``pipeline.process_pending_alert_deliveries``): with the notifier also
    retrying, one alert could be sent up to 3 × ALERT_RETRY_MAX_ATTEMPTS times
    on two different backoff curves, and a queue-level "attempt" meant three
    network calls.
    """

    channel = "webhook"

    def __init__(
        self,
        url: str,
        secret: str,
        timeout: int = 10,
    ) -> None:
        self._url = url
        self._secret = secret
        self._timeout = timeout

    async def send(self, event: AlertEvent) -> None:
        """POST the event JSON; signs it when a secret is configured.

        A missing secret is warned about once (unsigned payloads), not failed:
        delivery semantics are the retry queue's concern. Raises on transport
        or HTTP errors so the caller can queue a retry.
        """
        global _WEBHOOK_NO_SECRET_LOGGED  # noqa: PLW0603
        body = event.model_dump_json(indent=None).encode()
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._secret:
            headers["X-Orchestrator-Signature"] = _hmac_signature(self._secret, body)
        elif not _WEBHOOK_NO_SECRET_LOGGED:
            logger.warning(
                "Webhook configured without a secret — requests will not be signed. "
                "Set ALERT_WEBHOOK_SECRET to enable HMAC-SHA256 signatures."
            )
            _WEBHOOK_NO_SECRET_LOGGED = True
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            # Timeouts and network errors propagate as-is; the queue classifies
            # and retries them.
            resp = await client.post(self._url, content=body, headers=headers)
        if resp.status_code >= 400:
            # Not raise_for_status(): its message embeds the full URL, and
            # hosted webhooks (Slack, Teams, Discord) carry their secret in the
            # path. This string ends up in runs.error, alert_deliveries.last_error
            # and the logs, so it must stay URL-free.
            raise httpx.HTTPStatusError(
                f"HTTP {resp.status_code}", request=resp.request, response=resp
            )


# ─── Email ────────────────────────────────────────────────────────────────────


class EmailNotifier(Notifier):
    """
    Send AlertEvent via SMTP.

    Body: plain text, localised via i18n.
    Subject: localised via i18n.
    STARTTLS: enabled when ALERT_SMTP_STARTTLS=true.
    """

    channel = "email"

    def __init__(
        self,
        host: str,
        port: int,
        user: str,
        password: str,
        from_addr: str,
        to_addrs: list[str],
        starttls: bool = True,
        language: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._host = host
        self._port = port
        # smtplib.SMTP() has no default timeout: a server that accepts the TCP
        # connection and never sends its banner would block the executor thread
        # and the awaiting pipeline indefinitely, leaving the run RUNNING and
        # the target's run guard held until restart.
        self._timeout = timeout
        self._user = user
        self._password = password
        self._from = from_addr
        self._to = to_addrs
        self._starttls = starttls
        self._language = language

    def _render(self, event: AlertEvent) -> tuple[str, str]:
        """Render the localised (subject, body) pair for an alert event."""
        lang = resolve_language(self._language)
        new_count = event.new_observable_count
        subject = t(
            "alert_subject",
            language=lang,
            target_fqdn=event.target_fqdn,
            new_count=new_count,
            risk_level=tv(event.risk_level, language=lang),
        )
        obs_lines = ""
        if event.new_observables:
            lines = [f"  [{o.stix_type}] {o.value}" for o in event.new_observables]
            obs_lines = "\n".join(lines) + "\n\n"
        elif new_count:
            obs_lines = t("alert_values_hidden", language=lang, count=new_count)

        finding_section = ""
        if event.finding_summary:
            finding_section = t(
                "alert_synthesis_prefix", language=lang, summary=event.finding_summary
            )

        body = t(
            "alert_body",
            language=lang,
            target_fqdn=event.target_fqdn,
            run_id=event.run_id,
            run_status=tv(event.run_status, language=lang),
            risk_level=tv(event.risk_level, language=lang),
            new_count=new_count,
            generated_at=event.generated_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            observables_section=obs_lines,
            finding_section=finding_section,
        )
        return subject, body

    async def send(self, event: AlertEvent) -> None:
        """Render and send the email, keeping smtplib off the event loop."""
        subject, body = self._render(event)
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = self._from
        msg["To"] = ", ".join(self._to)

        # smtplib is synchronous; run in executor to avoid blocking the event loop.
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._send_sync, msg)

    def _send_sync(self, msg: MIMEText) -> None:
        """Blocking SMTP send (executor thread): optional STARTTLS, optional login."""
        if self._starttls:
            with smtplib.SMTP(self._host, self._port, timeout=self._timeout) as smtp:
                smtp.ehlo()
                smtp.starttls(context=ssl.create_default_context())
                smtp.ehlo()
                if self._user:
                    smtp.login(self._user, self._password)
                smtp.sendmail(self._from, self._to, msg.as_string())
        else:
            with smtplib.SMTP(self._host, self._port, timeout=self._timeout) as smtp:
                if self._user:
                    smtp.login(self._user, self._password)
                smtp.sendmail(self._from, self._to, msg.as_string())


# ─── Factory ──────────────────────────────────────────────────────────────────

_WEBHOOK_WARNING_LOGGED = False
_EMAIL_WARNING_LOGGED = False


def build_notifiers(language: str | None = None) -> list[Notifier]:
    """
    Build configured notifiers.  Channels without configuration are omitted
    with a warning logged once at startup (call this at import/lifespan time).
    """
    global _WEBHOOK_WARNING_LOGGED, _EMAIL_WARNING_LOGGED  # noqa: PLW0603
    notifiers: list[Notifier] = []

    if settings.alert_webhook_url:
        notifiers.append(
            WebhookNotifier(
                url=settings.alert_webhook_url,
                secret=settings.alert_webhook_secret,
                timeout=settings.alert_timeout_seconds,
            )
        )
    else:
        if not _WEBHOOK_WARNING_LOGGED:
            logger.warning(t("alert_webhook_no_config"))
            _WEBHOOK_WARNING_LOGGED = True

    if settings.alert_smtp_host and settings.alert_email_to:
        to_list = [a.strip() for a in settings.alert_email_to.split(",") if a.strip()]
        notifiers.append(
            EmailNotifier(
                host=settings.alert_smtp_host,
                port=settings.alert_smtp_port,
                user=settings.alert_smtp_user,
                password=settings.alert_smtp_password,
                from_addr=settings.alert_smtp_from,
                to_addrs=to_list,
                starttls=settings.alert_smtp_starttls,
                language=language,
                timeout=float(settings.alert_timeout_seconds),
            )
        )
    else:
        if not _EMAIL_WARNING_LOGGED:
            logger.warning(t("alert_email_no_config"))
            _EMAIL_WARNING_LOGGED = True

    return notifiers


# ─── Dispatch helper ─────────────────────────────────────────────────────────

_RISK_ORDER = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def alert_case_reason(
    *,
    new_observable_count: int,
    risk_level: str,
    run_status: RunStatus,
    cfg: AlertsConfig,
) -> AlertCaseReason | None:
    """Which rule fires for this run, or None when no alert is due.

    New observables win over the risk level, which wins over a run failure:
    the reason names the strongest fact the operator should look at first.
    """
    if cfg.on_new_observables and new_observable_count > 0:
        return AlertCaseReason.NEW_OBSERVABLES
    if should_alert(
        new_observable_count=0,
        risk_level=risk_level,
        on_new_observables=False,
        min_risk_level=cfg.min_risk_level,
    ):
        return AlertCaseReason.RISK_LEVEL
    if cfg.on_run_failure and run_status == RunStatus.FAILED:
        return AlertCaseReason.RUN_FAILURE
    return None


def should_alert(
    *,
    new_observable_count: int,
    risk_level: str,
    on_new_observables: bool,
    min_risk_level: str,
) -> bool:
    """
    Return True if an alert should be dispatched given the run results.

    Triggers when:
      - on_new_observables is True AND there are new observables, OR
      - finding risk_level >= min_risk_level
    """
    if on_new_observables and new_observable_count > 0:
        return True
    run_order = _RISK_ORDER.get(risk_level, 0)
    min_order = _RISK_ORDER.get(min_risk_level, _RISK_ORDER["high"])
    return run_order >= min_order

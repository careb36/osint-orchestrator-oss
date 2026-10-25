"""
Localisation of operator-facing text.

See docs/adr/ADR-004-language-policy.md for the rule this implements. In
short: anything a person reads as prose — API error details, report bodies,
LLM synthesis — is localised; anything a developer or a machine reads —
source, log messages, STIX vocabulary, enum values persisted to the database
— stays English.

The catalogue is a plain nested dict rather than gettext/.po files. At this
size that machinery would cost more than it returns, and the completeness
test in tests/unit/test_i18n.py gives the property that actually matters:
a key missing a translation fails CI rather than silently rendering the
wrong language at runtime.
"""

from __future__ import annotations

import logging

from orchestrator.config import settings

logger = logging.getLogger(__name__)

DEFAULT_LANGUAGE = "es"
SUPPORTED_LANGUAGES = frozenset({"es", "en"})

# key → language → template. Every key MUST carry every supported language;
# test_catalogue_is_complete enforces it.
_MESSAGES: dict[str, dict[str, str]] = {
    "target_not_found": {
        "es": "No existe el objetivo '{target_id}'",
        "en": "Target '{target_id}' not found",
    },
    "target_disabled": {
        "es": "El objetivo '{target_id}' está deshabilitado",
        "en": "Target '{target_id}' is disabled",
    },
    "alert_not_found": {
        "es": "No existe el caso de alerta {case_id}",
        "en": "Alert case {case_id} not found",
    },
    "alert_state_conflict": {
        "es": "El caso de alerta ya está en estado '{state}'",
        "en": "Alert case is already '{state}'",
    },
    "run_not_found": {
        "es": "No existe la ejecución {run_id}",
        "en": "Run {run_id} not found",
    },
    "run_already_in_progress": {
        "es": "Ya hay una ejecución activa para el objetivo '{target_id}'",
        "en": "An active run already exists for target '{target_id}'",
    },
    "report_not_found": {
        "es": "No existe reporte para la ejecución {run_id}",
        "en": "Report for run {run_id} not found",
    },
    "report_pdf_not_found": {
        "es": "La corrida {run_id} no tiene informe en PDF",
        "en": "Run {run_id} has no PDF report",
    },
    "bundle.not_found": {
        "es": "La corrida {run_id} no tiene artefactos para exportar",
        "en": "Run {run_id} has no artefacts to export",
    },
    "synthesis_skipped": {
        "es": "Síntesis omitida: no hay proveedor LLM configurado.",
        "en": "Synthesis skipped: no LLM provider is configured.",
    },
    "synthesis_failed": {
        "es": "La síntesis LLM no pudo completarse: el modelo devolvió una respuesta inválida dos veces. Último error: {error}",
        "en": "LLM synthesis could not be completed: the model returned an invalid response twice. Last error: {error}",
    },
    "synthesis_unavailable": {
        "es": "Síntesis LLM no disponible para esta ejecución: el proveedor falló o devolvió una respuesta inválida. Ver el campo error de la ejecución.",
        "en": "LLM synthesis unavailable for this run: the provider failed or returned an invalid response. See the run's error field.",
    },
    "finding_not_found": {
        "es": "No existe finding para la ejecución {run_id}",
        "en": "Finding for run {run_id} not found",
    },
    "pdf_page_of": {
        "es": "Página {page} de {total}",
        "en": "Page {page} of {total}",
    },
    "alert_subject": {
        "es": "Alerta OSINT: {target_fqdn} — {new_count} nuevo(s), riesgo {risk_level}",
        "en": "OSINT Alert: {target_fqdn} — {new_count} new, risk {risk_level}",
    },
    "alert_body": {
        "es": (
            "Alerta del orquestador OSINT\n\n"
            "Objetivo  : {target_fqdn}\n"
            "Run ID    : {run_id}\n"
            "Estado    : {run_status}\n"
            "Riesgo    : {risk_level}\n"
            "Nuevos    : {new_count}\n"
            "Generado  : {generated_at}\n\n"
            "{observables_section}"
            "{finding_section}"
        ),
        "en": (
            "OSINT Orchestrator Alert\n\n"
            "Target    : {target_fqdn}\n"
            "Run ID    : {run_id}\n"
            "Status    : {run_status}\n"
            "Risk      : {risk_level}\n"
            "New obs.  : {new_count}\n"
            "Generated : {generated_at}\n\n"
            "{observables_section}"
            "{finding_section}"
        ),
    },
    "socialosint_note_unverified": {
        "es": "[análisis de SocialOSINT, no verificado]\n\n{report}",
        "en": "[SocialOSINT analysis, unverified]\n\n{report}",
    },
    "socialosint_note_platforms_skipped": {
        "es": "Plataformas omitidas por falta de credenciales: {platforms}",
        "en": "Platforms skipped for lack of credentials: {platforms}",
    },
    "alert_webhook_no_config": {
        "es": "Canal webhook omitido: ALERT_WEBHOOK_URL no configurado.",
        "en": "Webhook channel skipped: ALERT_WEBHOOK_URL is not configured.",
    },
    "alert_email_no_config": {
        "es": "Canal email omitido: ALERT_SMTP_HOST o ALERT_EMAIL_TO no configurados.",
        "en": "Email channel skipped: ALERT_SMTP_HOST or ALERT_EMAIL_TO is not configured.",
    },
    "alert_values_hidden": {
        "es": "  ({count} observable(s) — valores ocultos)\n\n",
        "en": "  ({count} observable(s) — values hidden)\n\n",
    },
    "alert_synthesis_prefix": {
        "es": "Síntesis: {summary}\n",
        "en": "Synthesis: {summary}\n",
    },
    "api_key_missing": {
        "es": "Falta la clave de API: envíe la cabecera X-API-Key o Authorization: Bearer",
        "en": "API key missing: send the X-API-Key header or Authorization: Bearer",
    },
    "api_key_invalid": {
        "es": "Clave de API inválida",
        "en": "Invalid API key",
    },
    "metrics_disabled": {
        "es": "Las métricas están deshabilitadas (ORCHESTRATOR_METRICS_ENABLED=false)",
        "en": "Metrics are disabled (ORCHESTRATOR_METRICS_ENABLED=false)",
    },
    "opencti_sink_disabled": {
        "es": "La ingesta a OpenCTI está deshabilitada (OPENCTI_ENABLED=false)",
        "en": "OpenCTI ingest is disabled (OPENCTI_ENABLED=false)",
    },
    "bundle.invalid_json": {
        "es": "El cuerpo no es JSON válido: {error}",
        "en": "The request body is not valid JSON: {error}",
    },
    "bundle.contract_violation": {
        "es": "El bundle no cumple el contrato: {error}",
        "en": "The bundle does not satisfy the contract: {error}",
    },
    "bundle.parse_failed": {
        "es": "No se pudo interpretar el bundle STIX: {error}",
        "en": "The STIX bundle cannot be parsed: {error}",
    },
    "bundle.ingest_failed": {
        "es": "La ingesta en OpenCTI falló: {error}",
        "en": "OpenCTI ingest failed: {error}",
    },
    "bundle.ingest_unavailable": {
        "es": "No se pudo entregar el bundle a OpenCTI; reintente más tarde",
        "en": "The bundle could not be delivered to OpenCTI; retry later",
    },
    "manifest.not_found": {
        "es": "No existe el manifiesto de la ejecución {run_id}",
        "en": "Manifest for run {run_id} not found",
    },
    "chain.reason.artefact_hash": {
        "es": "El hash del artefacto '{name}' no coincide",
        "en": "Artifact hash mismatch for '{name}'",
    },
    "chain.reason.artefact_missing": {
        "es": "Falta el artefacto '{name}'",
        "en": "Artifact '{name}' is missing",
    },
    "chain.reason.manifest_missing": {
        "es": "No se encontró el manifiesto del run {run_id}",
        "en": "Manifest missing for run {run_id}",
    },
    "chain.reason.signature": {
        "es": "El manifiesto se modificó después de la ejecución (su hash no coincide con el registrado)",
        "en": "The manifest was modified after the run (its hash does not match the recorded one)",
    },
    "chain.reason.signature_key": {
        "es": "La firma del manifiesto no coincide con la clave configurada",
        "en": "Manifest signature does not match the configured key",
    },
    "chain.reason.chain_link": {
        "es": "La cadena de manifiestos está rota",
        "en": "Manifest chain link is broken",
    },
    "chain.reason.unsupported_version": {
        "es": "La versión del manifiesto no es compatible",
        "en": "Manifest version is unsupported",
    },
    "landing_title": {
        "es": "Orquestador OSINT",
        "en": "OSINT Orchestrator",
    },
    "landing_heading": {
        "es": "Orquestador OSINT",
        "en": "OSINT Orchestrator",
    },
    "landing_intro": {
        "es": "El servicio está activo. Use uno de estos accesos:",
        "en": "The service is running. Use one of the entry points below:",
    },
    "landing_docs": {
        "es": "Documentación de la API",
        "en": "API documentation",
    },
    "landing_health": {
        "es": "Chequeo de salud",
        "en": "Health check",
    },
    "landing_console": {
        "es": "Panel del operador (requiere API key)",
        "en": "Operator dashboard (requires API key)",
    },
    "landing_status": {
        "es": "En línea",
        "en": "Online",
    },
    # /console without a dashboard build (orchestrator/static/ui-dist missing).
    "dashboard_missing_title": {
        "es": "El panel del operador no está instalado",
        "en": "The operator dashboard is not installed",
    },
    "dashboard_missing_body": {
        "es": (
            "Este servicio corre desde un checkout sin el build del panel. Las imágenes "
            "Docker lo construyen solas; en un checkout, constrúyalo y cópielo así:"
        ),
        "en": (
            "This service runs from a checkout without the dashboard build. The Docker "
            "images build it themselves; from a checkout, build and copy it like this:"
        ),
    },
    "dashboard_missing_back": {
        "es": "Volver al inicio",
        "en": "Back to the landing page",
    },
}


# Stable English identifiers (persisted, compared, filtered on) → the label an
# operator reads. The identifier itself never changes (ADR-004); only the
# rendering does. ``tv`` returns the identifier unchanged when it is not
# listed, so a new enum value degrades to its code instead of raising inside
# a report or an e-mail.
_VALUES: dict[str, dict[str, str]] = {
    # Run status
    "pending": {"es": "pendiente", "en": "pending"},
    "running": {"es": "en curso", "en": "running"},
    "success": {"es": "exitosa", "en": "success"},
    "partial": {"es": "parcial", "en": "partial"},
    "failed": {"es": "fallida", "en": "failed"},
    # Risk level and evidence relevance
    "unknown": {"es": "desconocido", "en": "unknown"},
    "low": {"es": "bajo", "en": "low"},
    "medium": {"es": "medio", "en": "medium"},
    "high": {"es": "alto", "en": "high"},
    "critical": {"es": "crítico", "en": "critical"},
    # Evidence relevance (agrees with "relevancia", feminine in Spanish)
    "relevance.high": {"es": "alta", "en": "high"},
    "relevance.medium": {"es": "media", "en": "medium"},
    "relevance.low": {"es": "baja", "en": "low"},
    # Evidence category
    "adverse_media": {"es": "prensa adversa", "en": "adverse media"},
    "sanctions": {"es": "sanciones", "en": "sanctions"},
    "litigation": {"es": "litigios", "en": "litigation"},
    "regulatory_action": {"es": "acción regulatoria", "en": "regulatory action"},
    "corporate_profile": {"es": "perfil societario", "en": "corporate profile"},
    "unrelated": {"es": "no relacionado", "en": "unrelated"},
    # Collector outcome
    "ok": {"es": "correcto", "en": "ok"},
    "error": {"es": "error", "en": "error"},
    # STIX observable types the collectors emit
    "domain-name": {"es": "dominio", "en": "domain"},
    "ipv4-addr": {"es": "dirección IPv4", "en": "IPv4 address"},
    "ipv6-addr": {"es": "dirección IPv6", "en": "IPv6 address"},
    "email-addr": {"es": "correo electrónico", "en": "e-mail address"},
    "url": {"es": "enlace", "en": "URL"},
    "autonomous-system": {"es": "sistema autónomo", "en": "autonomous system"},
    "x509-certificate": {"es": "certificado TLS", "en": "TLS certificate"},
    "user-account": {"es": "cuenta de usuario", "en": "user account"},
    "identity": {"es": "identidad", "en": "identity"},
    "indicator": {"es": "indicador", "en": "indicator"},
    "file": {"es": "archivo", "en": "file"},
    # STIX relationship types
    "resolves-to": {"es": "resuelve a", "en": "resolves to"},
    "related-to": {"es": "relacionado con", "en": "related to"},
    "belongs-to": {"es": "pertenece a", "en": "belongs to"},
}


def tv(value: str, *, language: str | None = None) -> str:
    """Label for a stable identifier (status, risk, category, STIX type).

    Unknown identifiers come back unchanged: an operator sees the code, the
    run does not fail. Compare with ``t``, which raises for a typo in a
    message key because that is a bug, not a value.
    """
    translations = _VALUES.get(value)
    if translations is None:
        return value
    return translations[resolve_language(language)]


def resolve_language(preferred: str | None = None) -> str:
    """
    Return the language to render in, most specific source first.

    Order: an explicit per-target override, then the global setting, then
    DEFAULT_LANGUAGE. An unrecognised value is warned about and skipped
    rather than raising — a typo in targets.yaml should not take a
    scheduled run down, and English text is a far smaller failure than no
    collection at all.
    """
    for candidate in (preferred, settings.orchestrator_language):
        if not candidate:
            continue
        normalised = candidate.strip().lower()
        if normalised in SUPPORTED_LANGUAGES:
            return normalised
        logger.warning(
            "Unsupported language %r; supported: %s",
            candidate,
            sorted(SUPPORTED_LANGUAGES),
        )
    return DEFAULT_LANGUAGE


def t(key: str, *, language: str | None = None, **kwargs: object) -> str:
    """
    Render the message *key* in the resolved language.

    Raises KeyError for an unknown key. Returning the key itself would let a
    typo reach an operator as `target_not_fuond` and look like a value rather
    than a bug; failing loudly keeps that in CI, where the catalogue test
    already runs.
    """
    try:
        translations = _MESSAGES[key]
    except KeyError:
        raise KeyError(f"Unknown message key: {key!r}") from None

    lang = resolve_language(language)
    # resolve_language only returns supported languages, and the catalogue
    # test guarantees each key carries them all, so this cannot miss.
    return translations[lang].format(**kwargs)

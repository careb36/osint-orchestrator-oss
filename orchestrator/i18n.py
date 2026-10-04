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
        "es": "Consola de operaciones (requiere API key)",
        "en": "Operator console (requires API key)",
    },
    "console_page_title": {
        "es": "Consola de operaciones OSINT",
        "en": "OSINT operator console",
    },
    "console_title": {
        "es": "Consola mínima de operaciones",
        "en": "Minimal operator console",
    },
    "console_skip_to_main": {
        "es": "Saltar al contenido principal",
        "en": "Skip to main content",
    },
    "console_language": {
        "es": "Idioma",
        "en": "Language",
    },
    "console_api_key": {
        "es": "API key",
        "en": "API key",
    },
    "console_save": {
        "es": "Usar clave",
        "en": "Use key",
    },
    "console_clear": {
        "es": "Borrar clave",
        "en": "Clear key",
    },
    "console_remember_key": {
        "es": "Recordar en este navegador",
        "en": "Remember in this browser",
    },
    "console_remember_warning": {
        "es": "⚠️ Guarda en sessionStorage de este navegador.",
        "en": "⚠️ Stores in this browser sessionStorage.",
    },
    "console_key_note": {
        "es": "La clave queda solo en memoria de la sesión del navegador.",
        "en": "Key is kept only in browser session memory.",
    },
    "console_key_loaded": {
        "es": "Clave cargada desde almacenamiento de sesión.",
        "en": "Key loaded from session storage.",
    },
    "console_key_cleared": {
        "es": "Clave eliminada. Ingrésala de nuevo para continuar.",
        "en": "Key cleared. Enter it again to continue.",
    },
    "console_summary": {
        "es": "Resumen",
        "en": "Summary",
    },
    "console_risk": {
        "es": "Riesgo y tendencias",
        "en": "Risk & trends",
    },
    "console_runs": {
        "es": "Ejecuciones",
        "en": "Runs",
    },
    "console_detail": {
        "es": "Detalle",
        "en": "Detail",
    },
    "console_run_id": {
        "es": "ID de ejecución",
        "en": "Run ID",
    },
    "console_load_run": {
        "es": "Cargar",
        "en": "Load",
    },
    "console_loading": {
        "es": "Cargando...",
        "en": "Loading...",
    },
    "console_empty": {
        "es": "Sin datos para mostrar.",
        "en": "No data to display.",
    },
    "console_error_prefix": {
        "es": "Error",
        "en": "Error",
    },
    "console_target_all": {
        "es": "Todos los targets",
        "en": "All targets",
    },
    "console_all_statuses": {
        "es": "Todos los estados",
        "en": "All statuses",
    },
    "console_target_filter": {
        "es": "Filtrar por target",
        "en": "Filter by target",
    },
    "console_status_filter": {
        "es": "Filtrar por estado",
        "en": "Filter by status",
    },
    "console_last_run": {
        "es": "Última ejecución",
        "en": "Last run",
    },
    "console_status": {
        "es": "Estado",
        "en": "Status",
    },
    "console_new_observables": {
        "es": "Nuevos observables",
        "en": "New observables",
    },
    "console_target": {
        "es": "Target",
        "en": "Target",
    },
    "console_started_at": {
        "es": "Inicio",
        "en": "Started",
    },
    "console_finished_at": {
        "es": "Fin",
        "en": "Finished",
    },
    "console_actions": {
        "es": "Acciones",
        "en": "Actions",
    },
    "console_open_detail": {
        "es": "Abrir detalle",
        "en": "Open detail",
    },
    "console_report": {
        "es": "Reporte",
        "en": "Report",
    },
    "console_finding": {
        "es": "Hallazgo",
        "en": "Finding",
    },
    "console_errors": {
        "es": "Errores",
        "en": "Errors",
    },
    "console_delta_count": {
        "es": "Observables nuevos (delta)",
        "en": "New observables (delta)",
    },
    "console_run_table_caption": {
        "es": "Ejecuciones recientes",
        "en": "Recent runs",
    },
    "console_summary_table_caption": {
        "es": "Estado reciente por target",
        "en": "Latest status by target",
    },
    "console_risk_table_caption": {
        "es": "Tendencia de riesgo por target",
        "en": "Risk trend by target",
    },
    "console_status_pending": {
        "es": "pendiente",
        "en": "pending",
    },
    "console_status_running": {
        "es": "en ejecución",
        "en": "running",
    },
    "console_status_success": {
        "es": "exitoso",
        "en": "success",
    },
    "console_status_partial": {
        "es": "parcial",
        "en": "partial",
    },
    "console_status_failed": {
        "es": "fallido",
        "en": "failed",
    },
    "console_latest_risk": {
        "es": "Riesgo actual",
        "en": "Current risk",
    },
    "console_peak_risk": {
        "es": "Riesgo pico",
        "en": "Peak risk",
    },
    "console_trend_window": {
        "es": "Historial",
        "en": "History",
    },
    "console_risk_trend": {
        "es": "Tendencia",
        "en": "Trend",
    },
    "console_observables_trend": {
        "es": "Nuevos observables (historial)",
        "en": "New observables (history)",
    },
    "console_risk_unknown": {
        "es": "desconocido",
        "en": "unknown",
    },
    "console_risk_low": {
        "es": "bajo",
        "en": "low",
    },
    "console_risk_medium": {
        "es": "medio",
        "en": "medium",
    },
    "console_risk_high": {
        "es": "alto",
        "en": "high",
    },
    "console_risk_critical": {
        "es": "crítico",
        "en": "critical",
    },
    "console_auth_401_title": {
        "es": "Acceso denegado (401).",
        "en": "Access denied (401).",
    },
    "console_auth_401_body": {
        "es": 'Verifica la API key, luego pulsa "Usar clave".',
        "en": 'Verify the API key, then click "Use key".',
    },
}

_CONSOLE_I18N_KEYS = (
    "console_page_title",
    "console_title",
    "console_skip_to_main",
    "console_language",
    "console_api_key",
    "console_save",
    "console_clear",
    "console_remember_key",
    "console_remember_warning",
    "console_key_note",
    "console_key_loaded",
    "console_key_cleared",
    "console_summary",
    "console_risk",
    "console_runs",
    "console_detail",
    "console_run_id",
    "console_load_run",
    "console_loading",
    "console_empty",
    "console_error_prefix",
    "console_target_all",
    "console_all_statuses",
    "console_target_filter",
    "console_status_filter",
    "console_last_run",
    "console_status",
    "console_new_observables",
    "console_target",
    "console_started_at",
    "console_finished_at",
    "console_actions",
    "console_open_detail",
    "console_report",
    "console_finding",
    "console_errors",
    "console_delta_count",
    "console_run_table_caption",
    "console_summary_table_caption",
    "console_risk_table_caption",
    "console_status_pending",
    "console_status_running",
    "console_status_success",
    "console_status_partial",
    "console_status_failed",
    "console_latest_risk",
    "console_peak_risk",
    "console_trend_window",
    "console_risk_trend",
    "console_observables_trend",
    "console_risk_unknown",
    "console_risk_low",
    "console_risk_medium",
    "console_risk_high",
    "console_risk_critical",
    "console_auth_401_title",
    "console_auth_401_body",
)


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


def console_i18n_catalogue() -> dict[str, dict[str, str]]:
    """
    Return console translation keys as a JS-friendly dictionary.

    Shape: {language: {consoleKey: value}} where consoleKey has the ``console_``
    prefix removed and translated from snake_case to camelCase.
    """
    catalogue = {language: {} for language in SUPPORTED_LANGUAGES}
    for key in _CONSOLE_I18N_KEYS:
        console_key = _to_console_key(key)
        for language in SUPPORTED_LANGUAGES:
            catalogue[language][console_key] = _MESSAGES[key][language]
    return catalogue


def _to_console_key(message_key: str) -> str:
    if not message_key.startswith("console_"):
        return message_key
    chunks = message_key.removeprefix("console_").split("_")
    return chunks[0] + "".join(chunk.capitalize() for chunk in chunks[1:])

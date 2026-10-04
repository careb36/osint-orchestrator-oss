"""
Tests for orchestrator.i18n — the ADR-004 language policy.

The property worth protecting is not that a given string reads well, but that
the mechanism cannot silently fall back to the wrong language or to a missing
translation. A half-translated catalogue that renders an English string inside
a Spanish report is exactly the failure this suite exists to prevent.
"""

from __future__ import annotations

import pytest

from orchestrator.config import Settings, settings
from orchestrator.i18n import (
    _MESSAGES,
    DEFAULT_LANGUAGE,
    SUPPORTED_LANGUAGES,
    console_i18n_catalogue,
    resolve_language,
    t,
)
from orchestrator.models import Target


@pytest.fixture(autouse=True)
def _pinned_global_language(monkeypatch: pytest.MonkeyPatch):
    """
    Pin the global setting so these tests do not silently depend on the
    developer's own ORCHESTRATOR_LANGUAGE. Tests that exercise the global
    layer itself set it explicitly.
    """
    monkeypatch.setattr(settings, "orchestrator_language", DEFAULT_LANGUAGE)


# ── Configuration binding ─────────────────────────────────────────────────────


def test_setting_binds_to_orchestrator_language(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ORCHESTRATOR_LANGUAGE", "en")
    assert Settings(_env_file=None).orchestrator_language == "en"


def test_setting_ignores_the_hosts_gettext_language(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    LANGUAGE is a standard GNU gettext variable set on most Linux hosts. A
    bare `language` field would bind to it and make report language follow the
    host locale, which is why the field carries the orchestrator_ prefix.
    """
    monkeypatch.delenv("ORCHESTRATOR_LANGUAGE", raising=False)
    monkeypatch.setenv("LANGUAGE", "en_US:en")
    assert Settings(_env_file=None).orchestrator_language == DEFAULT_LANGUAGE


# ── Catalogue integrity ───────────────────────────────────────────────────────


def test_catalogue_is_complete() -> None:
    """Every key must carry every supported language."""
    missing = {
        key: sorted(SUPPORTED_LANGUAGES - set(translations))
        for key, translations in _MESSAGES.items()
        if SUPPORTED_LANGUAGES - set(translations)
    }
    assert missing == {}, f"keys missing translations: {missing}"


def test_catalogue_has_no_stray_languages() -> None:
    stray = {
        key: sorted(set(translations) - SUPPORTED_LANGUAGES)
        for key, translations in _MESSAGES.items()
        if set(translations) - SUPPORTED_LANGUAGES
    }
    assert stray == {}, f"keys with unsupported languages: {stray}"


@pytest.mark.parametrize("key", sorted(_MESSAGES))
def test_every_translation_takes_the_same_placeholders(key: str) -> None:
    """
    A placeholder present in one language but not another raises KeyError at
    render time — in whichever language happens to be configured.
    """
    import string

    def placeholders(template: str) -> set[str]:
        return {f for _, f, _, _ in string.Formatter().parse(template) if f}

    per_language = {lang: placeholders(tpl) for lang, tpl in _MESSAGES[key].items()}
    assert len(set(map(frozenset, per_language.values()))) == 1, per_language


def test_default_language_is_supported() -> None:
    assert DEFAULT_LANGUAGE in SUPPORTED_LANGUAGES


# ── Rendering ─────────────────────────────────────────────────────────────────


def test_renders_default_language_without_an_argument() -> None:
    assert t("target_not_found", target_id="mi-dominio") == ("No existe el objetivo 'mi-dominio'")


def test_explicit_language_wins() -> None:
    assert t("target_not_found", language="en", target_id="x") == "Target 'x' not found"


@pytest.mark.parametrize("language", sorted(SUPPORTED_LANGUAGES))
def test_placeholders_are_substituted_in_every_language(language: str) -> None:
    rendered = t("target_not_found", language=language, target_id="ejemplo.com")
    assert "ejemplo.com" in rendered
    assert "{" not in rendered


def test_unknown_key_raises_rather_than_echoing_itself() -> None:
    """Returning the key would reach an operator looking like a value."""
    with pytest.raises(KeyError, match="target_not_fuond"):
        t("target_not_fuond", target_id="x")


# ── Language resolution ───────────────────────────────────────────────────────


def test_resolution_prefers_the_explicit_override() -> None:
    assert resolve_language("en") == "en"


def test_resolution_falls_back_to_the_default() -> None:
    assert resolve_language(None) == DEFAULT_LANGUAGE


@pytest.mark.parametrize("value", ["EN", " en ", "Es"])
def test_resolution_is_case_and_whitespace_insensitive(value: str) -> None:
    assert resolve_language(value) in SUPPORTED_LANGUAGES


def test_global_setting_is_consulted_when_there_is_no_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The middle of the chain: target override → GLOBAL SETTING → default."""
    monkeypatch.setattr(settings, "orchestrator_language", "en")
    assert resolve_language(None) == "en"
    assert t("target_not_found", target_id="x") == "Target 'x' not found"


def test_override_beats_the_global_setting(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "orchestrator_language", "en")
    assert resolve_language("es") == "es"


def test_unsupported_global_falls_through_to_the_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A bad ORCHESTRATOR_LANGUAGE must not break rendering either."""
    monkeypatch.setattr(settings, "orchestrator_language", "klingon")
    assert resolve_language(None) == DEFAULT_LANGUAGE


def test_unsupported_language_degrades_instead_of_raising() -> None:
    """A typo in targets.yaml must not take a scheduled collection down."""
    assert resolve_language("klingon") == DEFAULT_LANGUAGE


# ── Per-target override ───────────────────────────────────────────────────────


def _target(**kwargs) -> Target:
    defaults = dict(id="t1", fqdn="example.com", authorization="self", purpose="test")
    defaults.update(kwargs)
    return Target(**defaults)


def test_target_defaults_to_no_override() -> None:
    assert _target().language is None


def test_target_override_is_honoured() -> None:
    assert t("target_disabled", language=_target(language="en").language, target_id="t1") == (
        "Target 't1' is disabled"
    )
    assert t("target_disabled", language=_target().language, target_id="t1") == (
        "El objetivo 't1' está deshabilitado"
    )


def test_risk_level_is_not_localised() -> None:
    """
    Finding.risk_level is persisted and compared, so it must stay an English
    identifier regardless of the configured language. ADR-004.
    """
    from orchestrator.models import Finding

    finding = Finding(target_id="t1", run_id=1, summary="resumen en español")
    assert finding.risk_level == "unknown"
    assert finding.risk_level not in {"desconocido", "desconocida"}


def test_console_i18n_catalogue_uses_supported_languages_only() -> None:
    catalogue = console_i18n_catalogue()
    assert set(catalogue) == SUPPORTED_LANGUAGES
    assert catalogue["es"]["pageTitle"]
    assert catalogue["en"]["pageTitle"]

from __future__ import annotations

from orchestrator.config import Settings


def test_env_file_is_ignored_when_orchestrator_env_file_is_empty(
    monkeypatch,
    tmp_path,
) -> None:
    (tmp_path / ".env").write_text("LLM_MODEL_REASONING=from-dotenv\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ORCHESTRATOR_ENV_FILE", "")
    monkeypatch.delenv("LLM_MODEL_REASONING", raising=False)

    assert Settings().llm_model_reasoning == ""


def test_env_file_is_read_by_default(monkeypatch, tmp_path) -> None:
    (tmp_path / ".env").write_text("LLM_MODEL_REASONING=from-dotenv\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ORCHESTRATOR_ENV_FILE", raising=False)
    monkeypatch.delenv("LLM_MODEL_REASONING", raising=False)

    assert Settings().llm_model_reasoning == "from-dotenv"

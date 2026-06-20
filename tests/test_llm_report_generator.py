import importlib
import urllib.error

from websecscope.reporter import llm_report_generator as llm


def test_build_prompt_uses_only_rule_based_payload():
    request = llm.LLMReportRequest(
        {
            "language": "en",
            "score": 95,
            "all_findings": [],
            "raw_secret": "must not be sent",
        },
        language="en",
    )

    prompt = llm.build_prompt(request)

    assert "rule-based JSON" in prompt
    assert "raw_secret" not in prompt


def test_generate_llm_report_success(monkeypatch):
    monkeypatch.setattr(llm, "call_ollama", lambda client, prompt, model: "Executive Summary")
    request = llm.LLMReportRequest({"language": "en", "all_findings": []}, language="en")

    report = llm.generate_llm_report(request)

    assert report["enabled"] is True
    assert report["content"] == "Executive Summary"
    assert report["error"] is None


def test_generate_llm_report_fallback(monkeypatch):
    def fail(client, prompt, model):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(llm, "call_ollama", fail)
    request = llm.LLMReportRequest({"language": "en", "all_findings": []}, language="en")

    report = llm.generate_llm_report(request)

    assert report["enabled"] is False
    assert "Ollama request failed" in report["error"]
    assert "rule-based" in report["note"]


def test_settings_env_override(monkeypatch):
    monkeypatch.setenv("WEBSECSCOPE_OLLAMA_MODEL", "custom-model")
    monkeypatch.setenv("WEBSECSCOPE_OLLAMA_TIMEOUT", "7")

    import websecscope.config.settings as settings

    reloaded = importlib.reload(settings)

    assert reloaded.OLLAMA_MODEL == "custom-model"
    assert reloaded.OLLAMA_TIMEOUT == 7

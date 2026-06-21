import importlib
import urllib.error

from websecscope.reporter.html_reporter import render_ai_report_section
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


def test_korean_prompt_requires_korean_only_sections():
    request = llm.LLMReportRequest(
        {"language": "ko", "score": 80, "all_findings": []},
        language="ko",
    )

    prompt = llm.build_prompt(request)

    assert "한국어로만 작성" in prompt
    assert "요약" in prompt
    assert "위험 분석" in prompt
    assert "우선 개선 권고" in prompt
    assert "영어 섹션명을 출력하지 마세요" in prompt


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


def test_korean_ai_report_renders_korean_section_names_and_markdown_lists():
    html = render_ai_report_section(
        {
            "content": (
                "## Executive Summary\n"
                "- 점검 결과 요약\n\n"
                "## Risk Analysis\n"
                "1. 위험 분석 내용\n\n"
                "## Priority Recommendations\n"
                "- 우선 개선 권고"
            ),
            "model": "qwen2.5:7b",
        },
        "ko",
    )

    assert "<h2>AI 리포트</h2>" in html
    assert "<h3>요약</h3>" in html
    assert "<h3>위험 분석</h3>" in html
    assert "<h3>우선 개선 권고</h3>" in html
    assert "<ul><li>점검 결과 요약</li></ul>" in html
    assert "<ol><li>위험 분석 내용</li></ol>" in html


def test_settings_env_override(monkeypatch):
    monkeypatch.setenv("WEBSECSCOPE_OLLAMA_MODEL", "custom-model")
    monkeypatch.setenv("WEBSECSCOPE_OLLAMA_TIMEOUT", "7")

    import websecscope.config.settings as settings

    reloaded = importlib.reload(settings)

    assert reloaded.OLLAMA_MODEL == "custom-model"
    assert reloaded.OLLAMA_TIMEOUT == 7

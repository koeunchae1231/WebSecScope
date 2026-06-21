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
            "raw_http_response": "must not be sent",
        },
        language="en",
    )

    prompt = llm.build_prompt(request)

    assert "rule-based JSON" in prompt
    assert "raw_secret" not in prompt
    assert "raw_http_response" not in prompt


def test_korean_prompt_requires_formatter_only_json():
    request = llm.LLMReportRequest(
        {"language": "ko", "score": 80, "all_findings": []},
        language="ko",
    )

    prompt = llm.build_prompt(request)

    assert "당신은 보안 분석기가 아닙니다." in prompt
    assert "Markdown과 HTML을 출력하지 마세요." in prompt
    assert "모든 사용자 문장은 한국어" in prompt
    assert "executive_summary" in prompt
    assert "risk_explanation" in prompt
    assert "priority_actions" in prompt
    assert "limitations" in prompt


def test_generate_llm_report_success_sanitizes_markdown(monkeypatch):
    monkeypatch.setattr(
        llm,
        "call_ollama",
        lambda client, prompt, model: "## Executive Summary\n- **Only scanner facts**\n<script>x</script>",
    )
    request = llm.LLMReportRequest({"language": "en", "all_findings": []}, language="en")

    report = llm.generate_llm_report(request)

    assert report["enabled"] is True
    assert "##" not in report["content"]
    assert "**" not in report["content"]
    assert "<script>" not in report["content"]
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


def test_korean_ai_report_renders_json_sections():
    html = render_ai_report_section(
        {
            "content": (
                '{"executive_summary":"점검 결과 요약",'
                '"risk_explanation":["위험 설명 내용"],'
                '"priority_actions":["우선 개선 권고"],'
                '"limitations":"Scanner 결과만으로는 확인할 수 없습니다."}'
            ),
            "model": "qwen2.5:7b",
        },
        "ko",
    )

    assert "<h2>AI 리포트</h2>" in html
    assert "<h3>요약</h3>" in html
    assert "<h3>위험 설명</h3>" in html
    assert "<h3>우선 조치</h3>" in html
    assert "<h3>점검 한계</h3>" in html
    assert "<li>위험 설명 내용</li>" in html


def test_settings_env_override(monkeypatch):
    monkeypatch.setenv("WEBSECSCOPE_OLLAMA_MODEL", "custom-model")
    monkeypatch.setenv("WEBSECSCOPE_OLLAMA_TIMEOUT", "7")

    import websecscope.config.settings as settings

    reloaded = importlib.reload(settings)

    assert reloaded.OLLAMA_MODEL == "custom-model"
    assert reloaded.OLLAMA_TIMEOUT == 7

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from websecscope.config.settings import (
    OLLAMA_MODEL,
    OLLAMA_TEMPERATURE,
    OLLAMA_TIMEOUT,
    OLLAMA_URL,
)

DEFAULT_MODEL = OLLAMA_MODEL
DEFAULT_OLLAMA_ENDPOINT = OLLAMA_URL
REQUEST_TIMEOUT_SECONDS = OLLAMA_TIMEOUT
DEFAULT_TEMPERATURE = OLLAMA_TEMPERATURE
KOREAN_SECTION_TITLES = ("요약", "위험 분석", "우선 개선 권고")
ENGLISH_SECTION_TITLES = (
    "Executive Summary",
    "Risk Analysis",
    "Priority Recommendations",
)


class LLMClient(Protocol):
    def generate(self, prompt: str, model: str = DEFAULT_MODEL) -> str:
        """Return narrative text for a prepared prompt."""


@dataclass(frozen=True)
class LLMReportRequest:
    rule_based_result: dict[str, Any]
    language: str = "ko"
    model: str = DEFAULT_MODEL
    endpoint: str = DEFAULT_OLLAMA_ENDPOINT


class OllamaClient:
    def __init__(
        self,
        endpoint: str = DEFAULT_OLLAMA_ENDPOINT,
        timeout_seconds: int = REQUEST_TIMEOUT_SECONDS,
        temperature: float = DEFAULT_TEMPERATURE,
    ) -> None:
        self.endpoint = endpoint
        self.timeout_seconds = timeout_seconds
        self.temperature = temperature

    def generate(self, prompt: str, model: str = DEFAULT_MODEL) -> str:
        payload = json.dumps(
            {
                "model": model,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": self.temperature},
            }
        ).encode("utf-8")
        request = Request(
            self.endpoint,
            data=payload,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "WebSecScope/2.0",
            },
        )
        with urlopen(request, timeout=self.timeout_seconds) as response:
            raw = response.read().decode("utf-8")
        data = json.loads(raw)
        return str(data.get("response", "")).strip()


def build_llm_prompt(request: LLMReportRequest) -> str:
    """Compatibility wrapper for callers that used the v2 prompt function."""
    return build_prompt(request)


def build_prompt(request: LLMReportRequest) -> str:
    """Build a localized prompt from rule-based scan JSON only."""
    result = _safe_rule_based_payload(request.rule_based_result)
    payload = json.dumps(result, ensure_ascii=False, indent=2)
    if request.language == "ko":
        return _korean_prompt(payload)
    return _english_prompt(payload)


def generate_llm_report(
    request: LLMReportRequest,
    client: LLMClient | None = None,
) -> dict[str, Any]:
    """Generate optional narrative output without changing rule-based findings."""
    prompt = build_prompt(request)
    llm_client = client or OllamaClient(endpoint=request.endpoint)
    try:
        content = call_ollama(llm_client, prompt, request.model)
    except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        return build_fallback_report(request, llm_client, prompt, exc)
    return build_success_report(request, llm_client, prompt, content)


def call_ollama(client: LLMClient, prompt: str, model: str) -> str:
    return client.generate(prompt, model=model)


def build_fallback_report(
    request: LLMReportRequest,
    client: LLMClient,
    prompt: str,
    error: Exception,
) -> dict[str, Any]:
    return {
        "enabled": False,
        "provider": client.__class__.__name__,
        "model": request.model,
        "endpoint": request.endpoint,
        "prompt": prompt,
        "content": None,
        "error": f"{type(error).__name__}: Ollama request failed",
        "note": "LLM report generation failed gracefully. Detection and reports remain rule-based.",
    }


def build_success_report(
    request: LLMReportRequest,
    client: LLMClient,
    prompt: str,
    content: str,
) -> dict[str, Any]:
    return {
        "enabled": True,
        "provider": client.__class__.__name__,
        "model": request.model,
        "endpoint": request.endpoint,
        "prompt": prompt,
        "content": content,
        "error": None,
        "note": "LLM output is narrative only and must not add findings.",
    }


def _korean_prompt(payload: str) -> str:
    section_titles = ", ".join(KOREAN_SECTION_TITLES)
    return f"""당신은 보안 취약점 탐지기가 아니라 보안 리포트 작성자입니다.

규칙:
- 아래 rule-based JSON만 근거로 사용하세요.
- 새로운 취약점, severity, CVE, endpoint, evidence를 만들지 마세요.
- 취약점 탐지는 이미 rule-based engine이 수행했습니다.
- evidence와 interpretation을 구분해서 설명하세요.
- 근거가 불충분하면 불충분하다고 말하세요.
- 출력은 한국어로만 작성하세요. 영어 문장으로 답변하지 마세요.
- 섹션 제목도 한국어로만 작성하세요.
- 반드시 다음 세 섹션만 작성하세요: {section_titles}.
- Executive Summary, Risk Analysis, Priority Recommendations 같은 영어 섹션명을 출력하지 마세요.
- 간결한 문단과 번호 목록 또는 bullet 목록을 사용하세요.

Rule-based JSON:
{payload}
"""


def _english_prompt(payload: str) -> str:
    section_titles = ", ".join(ENGLISH_SECTION_TITLES)
    return f"""You are a security report writer, not a vulnerability scanner.

Rules:
- Use only the rule-based JSON provided below.
- Do not invent new findings, severities, CVEs, endpoints, or evidence.
- Vulnerability detection was already performed by the rule-based engine.
- Keep evidence and interpretation separate.
- If evidence is inconclusive, say it is inconclusive.
- Write in English.
- Produce only these sections: {section_titles}.
- Use concise paragraphs and numbered lists.

Rule-based JSON:
{payload}
"""


def _safe_rule_based_payload(result: dict[str, Any]) -> dict[str, Any]:
    allowed_keys = {
        "scan_id",
        "version",
        "language",
        "generated_at",
        "target",
        "score",
        "grade",
        "findings_summary",
        "all_findings",
        "api_auth_findings",
        "linux_findings",
        "docker_findings",
        "service_findings",
        "cve_findings",
        "cve_lookup",
    }
    return {key: result.get(key) for key in allowed_keys if key in result}

from __future__ import annotations

import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from dataclasses import dataclass
from typing import Any, Protocol


DEFAULT_MODEL = "qwen2.5:7b"
DEFAULT_OLLAMA_ENDPOINT = "http://localhost:11434/api/generate"
REQUEST_TIMEOUT_SECONDS = 60


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
    def __init__(self, endpoint: str = DEFAULT_OLLAMA_ENDPOINT, timeout_seconds: int = REQUEST_TIMEOUT_SECONDS) -> None:
        self.endpoint = endpoint
        self.timeout_seconds = timeout_seconds

    def generate(self, prompt: str, model: str = DEFAULT_MODEL) -> str:
        payload = json.dumps(
            {
                "model": model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.2,
                },
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
    """Build a prompt that forbids LLM-based detection and uses only scanner output."""
    return build_prompt(request)


def build_prompt(request: LLMReportRequest) -> str:
    """Build a localized prompt from rule-based scan JSON only."""
    result = _safe_rule_based_payload(request.rule_based_result)
    payload = json.dumps(result, ensure_ascii=False, indent=2)
    if request.language == "ko":
        return _korean_prompt(payload)
    return _english_prompt(payload)


def generate_llm_report(request: LLMReportRequest, client: LLMClient | None = None) -> dict[str, Any]:
    """Generate an optional narrative report when a client is supplied.

    v2 intentionally does not make LLM output part of detection. Without a client,
    this returns a prepared prompt so the normal rule-based JSON/HTML report path
    continues to work unchanged.
    """
    prompt = build_prompt(request)
    if client is None:
        client = OllamaClient(endpoint=request.endpoint)
    try:
        content = call_ollama(client, prompt, request.model)
    except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        return build_fallback_report(request, client, prompt, exc)
    return build_success_report(request, client, prompt, content)


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
    return f"""당신은 보안 취약점 탐지기가 아니라 보안 리포트 작성자입니다.

규칙:
- 아래 rule-based JSON만 근거로 사용하세요.
- 새로운 취약점, severity, CVE, endpoint, evidence를 만들지 마세요.
- 취약점 탐지는 rule-based engine이 이미 수행했습니다.
- evidence와 interpretation을 구분해서 설명하세요.
- 근거가 불충분하면 불충분하다고 말하세요.
- 출력은 한국어로 작성하세요.
- 반드시 다음 세 섹션만 작성하세요: Executive Summary, Risk Analysis, Priority Recommendations.
- 간결한 문단과 번호 목록을 사용하세요.

Rule-based JSON:
{payload}
"""


def _english_prompt(payload: str) -> str:
    return f"""You are a security report writer, not a vulnerability scanner.

Rules:
- Use only the rule-based JSON provided below.
- Do not invent new findings, severities, CVEs, endpoints, or evidence.
- Vulnerability detection was already performed by the rule-based engine.
- Keep evidence and interpretation separate.
- If evidence is inconclusive, say it is inconclusive.
- Write in English.
- Produce only these sections: Executive Summary, Risk Analysis, Priority Recommendations.
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

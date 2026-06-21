from __future__ import annotations

import json
import re
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
KOREAN_SECTION_TITLES = ("요약", "위험 설명", "우선 조치", "점검 한계")
ENGLISH_SECTION_TITLES = (
    "Executive Summary",
    "Risk Explanation",
    "Priority Actions",
    "Limitations",
)
OUTPUT_KEYS = ("executive_summary", "risk_explanation", "priority_actions", "limitations")


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
    """Build a localized formatter prompt from scanner-approved JSON only."""
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
        "content": sanitize_llm_output(content, request.language, request.rule_based_result),
        "error": None,
        "note": "LLM output is narrative only and must not add findings.",
    }


def _korean_prompt(payload: str) -> str:
    section_titles = ", ".join(KOREAN_SECTION_TITLES)
    return f"""당신은 보안 분석기가 아닙니다.
당신은 보안 리포트 포맷터입니다.

규칙:
1. 아래 rule-based JSON에 있는 정보만 사용하세요.
2. 새로운 취약점, CVE, endpoint, evidence를 만들지 마세요.
3. severity를 변경하지 마세요.
4. 추측하지 마세요.
5. Markdown과 HTML을 출력하지 마세요.
6. 모든 사용자 문장은 한국어로 작성하세요.
7. 정보가 부족하면 "Scanner 결과만으로는 확인할 수 없습니다."라고 작성하세요.
8. 출력은 JSON 객체 하나만 사용하세요.
9. JSON key는 executive_summary, risk_explanation, priority_actions, limitations만 사용하세요.
10. 각 값은 문자열 또는 문자열 배열이어야 하며 섹션 의미는 다음과 같습니다: {section_titles}.

Rule-based JSON:
{payload}
"""


def _english_prompt(payload: str) -> str:
    section_titles = ", ".join(ENGLISH_SECTION_TITLES)
    return f"""You are a security report formatter, not a vulnerability scanner.

Rules:
- Use only the rule-based JSON provided below.
- Do not invent new findings, severities, CVEs, endpoints, or evidence.
- Vulnerability detection was already performed by the rule-based engine.
- Keep evidence and interpretation separate.
- If evidence is inconclusive, say it is inconclusive.
- Write in English.
- Do not output Markdown or HTML.
- Output one JSON object only.
- Use only these keys: executive_summary, risk_explanation, priority_actions, limitations.
- Each value must be a string or an array of strings.
- These keys map to these report sections: {section_titles}.

Rule-based JSON:
{payload}
"""


def _safe_rule_based_payload(result: dict[str, Any]) -> dict[str, Any]:
    findings = result.get("all_findings", result.get("findings", []))
    return {
        "target": result.get("target"),
        "security_score": result.get("score"),
        "grade": result.get("grade"),
        "severity_counts": _severity_counts(result),
        "findings": [_safe_finding(finding) for finding in findings],
        "recommendations": _recommendations(findings),
    }


def _severity_counts(result: dict[str, Any]) -> dict[str, Any]:
    summary = result.get("findings_summary") or result.get("summary") or {}
    return {
        key: summary.get(key, 0)
        for key in ("critical", "high", "medium", "low", "informational")
    }


def _safe_finding(finding: dict[str, Any]) -> dict[str, Any]:
    allowed = (
        "id",
        "check_id",
        "status",
        "severity",
        "severity_label",
        "category",
        "owasp_category",
        "title",
        "description",
        "interpretation",
        "evidence",
        "recommendation",
    )
    return {key: finding.get(key) for key in allowed if finding.get(key) not in (None, "")}


def _recommendations(findings: list[dict[str, Any]]) -> list[str]:
    seen: set[str] = set()
    values: list[str] = []
    for finding in findings:
        recommendation = str(finding.get("recommendation") or "").strip()
        if recommendation and recommendation not in seen:
            seen.add(recommendation)
            values.append(recommendation)
    return values


def sanitize_llm_output(
    content: str,
    language: str = "ko",
    result: dict[str, Any] | None = None,
) -> str:
    """Return plain report text/JSON with Markdown, HTML, and internal noise removed."""
    parsed = _parse_json_output(content)
    if parsed:
        return json.dumps(_normalize_output_object(parsed, language), ensure_ascii=False)
    if result is not None:
        return json.dumps(_deterministic_formatter_output(result, language), ensure_ascii=False)
    return _sanitize_plain_text(content, language)


def _deterministic_formatter_output(result: dict[str, Any], language: str) -> dict[str, Any]:
    safe = _safe_rule_based_payload(result)
    score = safe.get("security_score", "N/A")
    grade = safe.get("grade", "N/A")
    findings = safe.get("findings", [])
    failing = [finding for finding in findings if finding.get("status") != "PASS"]
    top = [
        finding
        for finding in failing
        if finding.get("severity") in {"critical", "high", "medium"}
    ][:3]
    if language == "ko":
        top_titles = ", ".join(str(finding.get("title")) for finding in top if finding.get("title"))
        return {
            "executive_summary": f"보안 점수는 {score}점({grade} 등급)입니다. Scanner가 확인한 진단 항목은 {len(findings)}개입니다.",
            "risk_explanation": (
                f"우선 검토할 위험은 {top_titles} 항목입니다."
                if top_titles
                else "우선순위가 높은 위험이 발견되지 않았습니다."
            ),
            "priority_actions": [
                str(finding.get("recommendation"))
                for finding in top
                if finding.get("recommendation")
            ]
            or ["탐지된 항목의 근거를 검토한 뒤 심각도가 높은 항목부터 개선하세요."],
            "limitations": "Scanner 결과만으로는 확인할 수 없습니다.",
        }
    top_titles = ", ".join(str(finding.get("title")) for finding in top if finding.get("title"))
    return {
        "executive_summary": f"The security score is {score} ({grade}). The scanner reported {len(findings)} findings.",
        "risk_explanation": (
            f"The priority risks are {top_titles}."
            if top_titles
            else "No high-priority risks were identified."
        ),
        "priority_actions": [
            str(finding.get("recommendation"))
            for finding in top
            if finding.get("recommendation")
        ]
        or ["Review the evidence and address the highest-severity findings first."],
        "limitations": "The scanner results are insufficient to confirm anything beyond the reported findings.",
    }


def _parse_json_output(content: str) -> dict[str, Any] | None:
    text = content.strip()
    candidates = [text]
    match = re.search(r"\{.*\}", text, flags=re.DOTALL)
    if match:
        candidates.append(match.group(0))
    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def _normalize_output_object(parsed: dict[str, Any], language: str) -> dict[str, Any]:
    fallback = (
        "Scanner 결과만으로는 확인할 수 없습니다."
        if language == "ko"
        else "The scanner results are insufficient to confirm this."
    )
    normalized: dict[str, Any] = {}
    for key in OUTPUT_KEYS:
        value = parsed.get(key)
        if isinstance(value, list):
            items = [_sanitize_line(str(item), language) for item in value if str(item).strip()]
            normalized[key] = items or [fallback]
        elif value:
            normalized[key] = _sanitize_line(str(value), language)
        else:
            normalized[key] = fallback
    return normalized


def _sanitize_plain_text(content: str, language: str) -> str:
    cleaned = []
    for raw_line in content.replace("\r\n", "\n").split("\n"):
        line = _sanitize_line(raw_line, language)
        if line:
            cleaned.append(line)
    fallback = "Scanner 결과만으로는 확인할 수 없습니다." if language == "ko" else "No AI content returned."
    return "\n".join(cleaned) or fallback


def _sanitize_line(value: str, language: str) -> str:
    line = re.sub(r"<[^>]+>", "", value.strip())
    line = re.sub(r"^#{1,6}\s*", "", line)
    line = re.sub(r"^[-*]\s+", "", line)
    line = re.sub(r"^\d+\.\s+", "", line)
    line = line.replace("**", "").replace("__", "").replace("`", "")
    line = _remove_internal_message(line, language)
    return line.strip()


def _remove_internal_message(line: str, language: str) -> str:
    internal_patterns = (
        "Traceback",
        "Exception",
        "Stack trace",
        "DEBUG",
        "INFO:",
        "ERROR:",
        "Ollama request failed",
    )
    if any(pattern.lower() in line.lower() for pattern in internal_patterns):
        return ""
    return line

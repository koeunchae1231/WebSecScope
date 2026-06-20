from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Protocol


DEFAULT_MODEL = "qwen2.5"


class LLMClient(Protocol):
    def generate(self, prompt: str, model: str = DEFAULT_MODEL) -> str:
        """Return narrative text for a prepared prompt."""


@dataclass(frozen=True)
class LLMReportRequest:
    rule_based_result: dict[str, Any]
    language: str = "ko"
    model: str = DEFAULT_MODEL


def build_llm_prompt(request: LLMReportRequest) -> str:
    """Build a prompt that forbids LLM-based detection and uses only scanner output."""
    result = _safe_rule_based_payload(request.rule_based_result)
    payload = json.dumps(result, ensure_ascii=False, indent=2)
    return f"""You are a security report writer, not a vulnerability scanner.

Rules:
- Use only the rule-based JSON provided below.
- Do not invent new findings, severities, CVEs, endpoints, or evidence.
- Keep evidence and interpretation separate.
- If evidence is inconclusive, say it is inconclusive.
- Write in language: {request.language}.
- Produce an executive summary, prioritized risk narrative, and remediation plan.

Rule-based JSON:
{payload}
"""


def generate_llm_report(request: LLMReportRequest, client: LLMClient | None = None) -> dict[str, Any]:
    """Generate an optional narrative report when a client is supplied.

    v2 intentionally does not make LLM output part of detection. Without a client,
    this returns a prepared prompt so the normal rule-based JSON/HTML report path
    continues to work unchanged.
    """
    prompt = build_llm_prompt(request)
    if client is None:
        return {
            "enabled": False,
            "provider": None,
            "model": request.model,
            "prompt": prompt,
            "content": None,
            "note": "LLM report generation is optional. Detection remains rule-based only.",
        }
    return {
        "enabled": True,
        "provider": client.__class__.__name__,
        "model": request.model,
        "prompt": prompt,
        "content": client.generate(prompt, model=request.model),
        "note": "LLM output is narrative only and must not add findings.",
    }


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

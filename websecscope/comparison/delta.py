from __future__ import annotations

from typing import Any

from websecscope.scoring.grade import grade_for_score

SEVERITIES = ("critical", "high", "medium", "low", "informational")


def score_delta(before_score: Any, after_score: Any) -> int | None:
    if isinstance(before_score, int) and isinstance(after_score, int):
        return after_score - before_score
    return None


def severity_delta(before: dict[str, Any], after: dict[str, Any]) -> dict[str, int]:
    before_counts = severity_counts(before)
    after_counts = severity_counts(after)
    return {severity: after_counts.get(severity, 0) - before_counts.get(severity, 0) for severity in SEVERITIES}


def severity_counts(result: dict[str, Any]) -> dict[str, int]:
    summary = result.get("findings_summary") or {}
    if summary:
        return {severity: int(summary.get(severity, 0) or 0) for severity in SEVERITIES}
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in all_findings(result):
        counts[severity_label(finding.get("severity", finding.get("risk")))] += 1
    return counts


def all_findings(result: dict[str, Any]) -> list[dict[str, Any]]:
    findings = result.get("all_findings")
    if isinstance(findings, list):
        return [finding for finding in findings if isinstance(finding, dict)]
    findings = result.get("findings")
    if isinstance(findings, list):
        return [finding for finding in findings if isinstance(finding, dict)]
    return []


def finding_id(finding: dict[str, Any]) -> str:
    return str(finding.get("id") or finding.get("check_id") or finding.get("title") or "")


def severity_label(value: Any) -> str:
    risk = str(value or "INFO").upper()
    if risk == "CRITICAL":
        return "critical"
    if risk == "HIGH":
        return "high"
    if risk == "MEDIUM":
        return "medium"
    if risk == "LOW":
        return "low"
    return "informational"


def grade_or_none(score: Any) -> str | None:
    return grade_for_score(score) if isinstance(score, int) else None

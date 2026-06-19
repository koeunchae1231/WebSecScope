from __future__ import annotations

from typing import Any

from websecscope.models import FAIL, WARNING, Finding, RISK_CRITICAL, RISK_HIGH, RISK_INFO, RISK_LOW, RISK_MEDIUM

RISK_WEIGHTS = {
    RISK_INFO: 0,
    RISK_LOW: 3,
    RISK_MEDIUM: 8,
    RISK_HIGH: 15,
    RISK_CRITICAL: 25,
}


def calculate_score(findings: list[Finding]) -> int:
    score = 100
    seen: set[tuple[str, str]] = set()
    for finding in findings:
        if _is_skipped(finding):
            continue
        dedupe_key = (finding.category, finding.title.lower())
        duplicate_multiplier = 0.35 if dedupe_key in seen else 1.0
        seen.add(dedupe_key)
        multiplier = _finding_multiplier(finding)
        penalty = RISK_WEIGHTS.get(_normalize_risk(finding.risk), 0)
        if finding.status == FAIL:
            score -= int(penalty * multiplier * duplicate_multiplier)
        elif finding.status == WARNING:
            warning_penalty = int((penalty // 2) * multiplier * duplicate_multiplier)
            score -= max(1, warning_penalty) if penalty else 0
    return max(0, min(100, score))


def grade_for_score(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def _finding_multiplier(finding: Finding) -> float:
    confidence = finding.metadata.get("confidence")
    if confidence == "low":
        return 0.5
    if confidence == "medium":
        return 0.7
    if finding.category == "cve":
        cvss_score = finding.metadata.get("cvss_score")
        if isinstance(cvss_score, (int, float)) and cvss_score < 4:
            return 0.6
    return 1.0


def _normalize_risk(risk: Any) -> str:
    value = str(risk or RISK_INFO).upper()
    if value in {"INFORMATIONAL", "INFO", "UNKNOWN"}:
        return RISK_INFO
    if value in {RISK_LOW, RISK_MEDIUM, RISK_HIGH, RISK_CRITICAL}:
        return value
    return RISK_INFO


def _is_skipped(finding: Finding) -> bool:
    text = f"{finding.check_id} {finding.title} {finding.evidence}".lower()
    return "skipped" in text or finding.metadata.get("skipped") is True

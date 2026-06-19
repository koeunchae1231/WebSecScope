from __future__ import annotations

from typing import Any

SEVERITIES = ("critical", "high", "medium", "low", "informational")


def compare_results(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    before_findings = {_finding_id(finding): finding for finding in _all_findings(before)}
    after_findings = {_finding_id(finding): finding for finding in _all_findings(after)}
    before_findings.pop("", None)
    after_findings.pop("", None)
    all_check_ids = sorted(set(before_findings) | set(after_findings))

    changes = []
    resolved_findings = []
    new_findings = []
    unchanged_findings = []
    for check_id in all_check_ids:
        before_finding = before_findings.get(check_id)
        after_finding = after_findings.get(check_id)
        before_status = before_finding.get("status") if before_finding else "MISSING"
        after_status = after_finding.get("status") if after_finding else "MISSING"
        if before_status == after_status:
            state = "UNCHANGED"
        elif before_status in {"FAIL", "WARNING"} and after_status == "PASS":
            state = "IMPROVED"
        elif before_status == "PASS" and after_status in {"FAIL", "WARNING"}:
            state = "REGRESSED"
        elif before_status == "MISSING":
            state = "NEW"
        elif after_status == "MISSING":
            state = "RESOLVED"
        else:
            state = "CHANGED"
        change = {
            "check_id": check_id,
            "id": check_id,
            "title": (after_finding or before_finding or {}).get("title", check_id),
            "before_status": before_status,
            "after_status": after_status,
            "state": state,
            "before_risk": before_finding.get("risk") if before_finding else None,
            "after_risk": after_finding.get("risk") if after_finding else None,
        }
        changes.append(change)
        if state in {"IMPROVED", "RESOLVED"}:
            resolved_findings.append(change)
        elif state in {"NEW", "REGRESSED"}:
            new_findings.append(change)
        elif state == "UNCHANGED":
            unchanged_findings.append(change)

    return {
        "before_scan_id": before.get("scan_id"),
        "after_scan_id": after.get("scan_id"),
        "before_score": before.get("score"),
        "after_score": after.get("score"),
        "score_delta": _score_delta(before.get("score"), after.get("score")),
        "before_grade": before.get("grade") or _grade_for_score(before.get("score")),
        "after_grade": after.get("grade") or _grade_for_score(after.get("score")),
        "resolved_findings": resolved_findings,
        "new_findings": new_findings,
        "unchanged_findings": unchanged_findings,
        "severity_delta": _severity_delta(before, after),
        "summary": {
            "improved": sum(1 for change in changes if change["state"] == "IMPROVED"),
            "regressed": sum(1 for change in changes if change["state"] == "REGRESSED"),
            "changed": sum(1 for change in changes if change["state"] == "CHANGED"),
            "new": sum(1 for change in changes if change["state"] == "NEW"),
            "resolved": sum(1 for change in changes if change["state"] == "RESOLVED"),
            "unchanged": sum(1 for change in changes if change["state"] == "UNCHANGED"),
        },
        "changes": changes,
    }


def _score_delta(before_score: Any, after_score: Any) -> int | None:
    if isinstance(before_score, int) and isinstance(after_score, int):
        return after_score - before_score
    return None


def _severity_delta(before: dict[str, Any], after: dict[str, Any]) -> dict[str, int]:
    before_counts = _severity_counts(before)
    after_counts = _severity_counts(after)
    return {severity: after_counts.get(severity, 0) - before_counts.get(severity, 0) for severity in SEVERITIES}


def _severity_counts(result: dict[str, Any]) -> dict[str, int]:
    summary = result.get("findings_summary") or {}
    if summary:
        return {severity: int(summary.get(severity, 0) or 0) for severity in SEVERITIES}
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in _all_findings(result):
        severity = _severity_label(finding.get("severity", finding.get("risk")))
        counts[severity] += 1
    return counts


def _all_findings(result: dict[str, Any]) -> list[dict[str, Any]]:
    findings = result.get("all_findings")
    if isinstance(findings, list):
        return [finding for finding in findings if isinstance(finding, dict)]
    findings = result.get("findings")
    if isinstance(findings, list):
        return [finding for finding in findings if isinstance(finding, dict)]
    return []


def _finding_id(finding: dict[str, Any]) -> str:
    return str(finding.get("id") or finding.get("check_id") or finding.get("title") or "")


def _severity_label(value: Any) -> str:
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


def _grade_for_score(score: Any) -> str | None:
    if not isinstance(score, int):
        return None
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"

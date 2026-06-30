from __future__ import annotations

from typing import Any

from websecscope.comparison.delta import all_findings, finding_id, grade_or_none, score_delta, severity_delta
from websecscope.comparison.summary import summarize_changes


def compare_results(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    before_findings = {finding_id(finding): finding for finding in all_findings(before)}
    after_findings = {finding_id(finding): finding for finding in all_findings(after)}
    before_findings.pop("", None)
    after_findings.pop("", None)

    check_ids = sorted(set(before_findings) | set(after_findings))
    changes = [_build_change(check_id, before_findings.get(check_id), after_findings.get(check_id)) for check_id in check_ids]
    return {
        "before_scan_id": before.get("scan_id"),
        "after_scan_id": after.get("scan_id"),
        "before_score": before.get("score"),
        "after_score": after.get("score"),
        "score_delta": score_delta(before.get("score"), after.get("score")),
        "before_grade": before.get("grade") or grade_or_none(before.get("score")),
        "after_grade": after.get("grade") or grade_or_none(after.get("score")),
        "resolved_findings": [change for change in changes if change["state"] in {"IMPROVED", "RESOLVED"}],
        "new_findings": [change for change in changes if change["state"] in {"NEW", "REGRESSED"}],
        "unchanged_findings": [change for change in changes if change["state"] == "UNCHANGED"],
        "severity_delta": severity_delta(before, after),
        "summary": summarize_changes(changes),
        "changes": changes,
    }


def _build_change(check_id: str, before_finding: dict[str, Any] | None, after_finding: dict[str, Any] | None) -> dict[str, Any]:
    before_status = before_finding.get("status") if before_finding else "MISSING"
    after_status = after_finding.get("status") if after_finding else "MISSING"
    return {
        "check_id": check_id,
        "id": check_id,
        "title": (after_finding or before_finding or {}).get("title", check_id),
        "before_status": before_status,
        "after_status": after_status,
        "state": _change_state(before_status, after_status),
        "before_risk": before_finding.get("risk") if before_finding else None,
        "after_risk": after_finding.get("risk") if after_finding else None,
    }


def _change_state(before_status: str, after_status: str) -> str:
    if before_status == after_status:
        return "UNCHANGED"
    if before_status in {"FAIL", "WARNING"} and after_status == "PASS":
        return "IMPROVED"
    if before_status == "PASS" and after_status in {"FAIL", "WARNING"}:
        return "REGRESSED"
    if before_status == "MISSING":
        return "NEW"
    if after_status == "MISSING":
        return "RESOLVED"
    return "CHANGED"

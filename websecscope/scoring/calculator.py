from __future__ import annotations

from typing import Any
from collections import defaultdict
from dataclasses import asdict
import hashlib
import json

from websecscope.models import FAIL, WARNING, Finding, RISK_CRITICAL, RISK_HIGH, RISK_INFO, RISK_LOW, RISK_MEDIUM
from websecscope.scoring.weights import RISK_WEIGHTS
from websecscope.finding_state import skip_reason

POLICY_VERSION = "scope-risk-v2-explicit-skip-v1"


def _scope(finding: Finding) -> tuple[dict[str, Any], str]:
    declared = finding.metadata.get("scoring_scope")
    if isinstance(declared, dict) and declared.get("kind") == "global":
        asset = declared.get("asset_id")
        if isinstance(asset, str) and asset.strip():
            return {"kind": "global", "asset_id": asset}, "explicit_global_asset"
    scope = {key: finding.metadata[key] for key in ("asset_id", "target", "host", "url", "path")
             if finding.metadata.get(key) is not None}
    if not any(key in scope for key in ("asset_id", "target", "host", "url")):
        scope["observation_evidence"] = finding.evidence
        return scope, "asset_unknown_exact_observation"
    return scope, "recorded_asset_and_path"


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _penalty(finding: Finding, duplicate: float) -> int:
    weight = RISK_WEIGHTS.get(_normalize_risk(finding.risk), 0)
    multiplier = _finding_multiplier(finding)
    if finding.status == FAIL:
        return int(weight * multiplier * duplicate)
    if finding.status == WARNING:
        return max(1, int((weight // 2) * multiplier * duplicate)) if weight else 0
    return 0


def calculate_score(findings: list[Finding], *, details: dict[str, Any] | None = None) -> int:
    calculation = calculate_score_details(findings)
    if details is not None:
        details.update(calculation)
    return calculation["score"]


def calculate_score_details(findings: list[Finding]) -> dict[str, Any]:
    """Group recorded observations and choose representatives independently of input order."""
    score = 100
    groups = defaultdict(list)
    prepared = []
    for index, finding in enumerate(findings):
        scope, scope_reason = _scope(finding)
        group_key = _json([finding.category, finding.check_id, scope])
        canonical = _json(asdict(finding))
        item = (index, finding, canonical, scope, scope_reason, group_key)
        if _is_skipped(finding):
            prepared.append((group_key, canonical, 2, item, None))
        else:
            groups[group_key].append(item)
    for group_key, items in groups.items():
        items.sort(key=lambda item: (-(_penalty(item[1], 1) - _penalty(item[1], .35)),
                                     -_penalty(item[1], 1), item[2]))
        for position, item in enumerate(items):
            prepared.append((group_key, item[2], 0 if position == 0 else 1, item,
                             1.0 if position == 0 else .35))
    prepared.sort(key=lambda item: item[:3])
    entries = []
    occurrences = defaultdict(int)
    for _, _, _, item, duplicate_multiplier in prepared:
        index, finding, canonical, scope, scope_reason, group_key = item
        skip_reason = _skip_reason(finding)
        multiplier = _finding_multiplier(finding)
        penalty = RISK_WEIGHTS.get(_normalize_risk(finding.risk), 0)
        deduction = 0 if skip_reason else _penalty(finding, duplicate_multiplier)
        status_base = penalty if finding.status == FAIL else penalty // 2 if finding.status == WARNING else 0
        applied = min(max(0, score), deduction)
        score -= deduction
        reason = skip_reason or ("pass" if finding.status == "PASS" else
                                "informational_risk" if not penalty else
                                "unsupported_status" if finding.status not in {FAIL, WARNING} else None)
        content_id = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        occurrences[content_id] += 1
        entries.append({
            "finding_id": f"finding-{index + 1:06d}", "finding_index": index,
            "content_id": content_id, "occurrence": occurrences[content_id],
            "group_id": hashlib.sha256(group_key.encode("utf-8")).hexdigest(),
            "scope": scope, "scope_reason": scope_reason,
            "representative": duplicate_multiplier == 1.0,
            "check_id": finding.check_id, "category": finding.category, "title": finding.title,
            "status": finding.status, "risk": finding.risk,
            "severity": {"INFO": "informational"}.get(_normalize_risk(finding.risk), _normalize_risk(finding.risk).lower()),
            "confidence": finding.metadata.get("confidence"), "cvss_score": finding.metadata.get("cvss_score"),
            "base_penalty": penalty,
            "status_factor": 1.0 if finding.status == FAIL else 0.5 if finding.status == WARNING else 0.0,
            "status_base_penalty": status_base, "confidence_multiplier": multiplier,
            "duplicate_multiplier": duplicate_multiplier,
            "computed_penalty": deduction, "final_penalty": applied,
            "clamp_reduction": deduction - applied,
            "skipped": bool(skip_reason), "excluded": reason is not None, "exclusion_reason": reason,
        })
    final_score = max(0, min(100, score))
    return {
        "policy_version": POLICY_VERSION,
        "initial_score": 100, "score": final_score, "unclamped_score": score,
        "total_computed_penalty": sum(entry["computed_penalty"] for entry in entries),
        "total_final_penalty": sum(entry["final_penalty"] for entry in entries),
        "clamp_adjustment": final_score - score,
        "entries": entries,
    }


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
    return _skip_reason(finding) is not None


def _skip_reason(finding: Finding) -> str | None:
    return skip_reason(finding.check_id, finding.metadata)

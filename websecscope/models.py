from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from websecscope.guide.mappings import recommendation_for_finding


PASS = "PASS"
FAIL = "FAIL"
WARNING = "WARNING"

RISK_INFO = "INFO"
RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"
RISK_CRITICAL = "CRITICAL"


@dataclass
class Finding:
    check_id: str
    category: str
    title: str
    status: str
    risk: str
    evidence: str
    recommendation: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        if not payload.get("recommendation"):
            payload["recommendation"] = recommendation_for_finding(self.check_id, self.category)
        payload["id"] = self.check_id
        payload["severity"] = _severity_label(self.risk)
        payload["description"] = self.metadata.get("description", self.title)
        return payload


@dataclass
class ScanResult:
    target: str
    findings: list[Finding]
    score: int
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    scan_id: str = field(default_factory=lambda: str(uuid4()))
    version: str = "1.0.0"
    metadata: dict[str, Any] = field(default_factory=dict)
    api_scan: dict[str, Any] = field(default_factory=dict)
    auth_scan: dict[str, Any] = field(default_factory=dict)
    linux_scan: dict[str, Any] = field(default_factory=dict)
    docker_scan: dict[str, Any] = field(default_factory=dict)
    service_detection: dict[str, Any] = field(default_factory=dict)
    version_detection: dict[str, Any] = field(default_factory=dict)
    cve_lookup: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        findings = [finding.to_dict() for finding in self.findings]
        findings_summary = summarize_findings(findings)
        api_auth_findings = [
            finding
            for finding in findings
            if finding.get("category") in {"api", "auth", "jwt", "cors", "idor", "rate_limit"}
        ]
        linux_findings = [finding for finding in findings if finding.get("category") == "linux"]
        docker_findings = [finding for finding in findings if finding.get("category") == "docker"]
        service_findings = [finding for finding in findings if finding.get("category") == "service"]
        cve_findings = [finding for finding in findings if finding.get("category") == "cve"]
        return {
            "scan_id": self.scan_id,
            "version": self.version,
            "generated_at": self.generated_at,
            "target": self.target,
            "score": self.score,
            "grade": _grade_for_score(self.score),
            "summary": summarize_findings(findings),
            "findings_summary": findings_summary,
            "findings": findings,
            "all_findings": findings,
            "api_scan": self.api_scan,
            "auth_scan": self.auth_scan,
            "api_auth_findings": api_auth_findings,
            "linux_scan": self.linux_scan,
            "linux_findings": linux_findings,
            "docker_scan": self.docker_scan,
            "docker_findings": docker_findings,
            "service_detection": self.service_detection,
            "version_detection": self.version_detection,
            "service_findings": service_findings,
            "cve_lookup": self.cve_lookup,
            "cve_findings": cve_findings,
            "metadata": self.metadata,
        }


def summarize_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    by_status = {PASS: 0, FAIL: 0, WARNING: 0}
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    categories: dict[str, int] = {}
    effective_seen: set[tuple[str, str]] = set()
    top_risks = []
    for finding in findings:
        by_status[finding.get("status", WARNING)] = by_status.get(finding.get("status", WARNING), 0) + 1
        category = finding.get("category", "unknown")
        categories[category] = categories.get(category, 0) + 1
        if _is_skipped_dict(finding):
            continue
        dedupe_key = (category, str(finding.get("title", finding.get("id", ""))).lower())
        if dedupe_key in effective_seen:
            continue
        effective_seen.add(dedupe_key)
        severity = _severity_label(finding.get("severity", finding.get("risk", RISK_INFO)))
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        if severity in {"critical", "high", "medium"} and finding.get("status") != PASS:
            top_risks.append(
                {
                    "id": finding.get("id", finding.get("check_id")),
                    "title": finding.get("title"),
                    "category": category,
                    "severity": severity,
                    "evidence": finding.get("evidence", ""),
                }
            )
    return {
        "total": len(findings),
        "effective_total": len(effective_seen),
        "critical": severity_counts["critical"],
        "high": severity_counts["high"],
        "medium": severity_counts["medium"],
        "low": severity_counts["low"],
        "informational": severity_counts["informational"],
        "categories": categories,
        "top_risks": top_risks[:10],
        "by_status": by_status,
        "by_risk": {
            RISK_INFO: severity_counts["informational"],
            RISK_LOW: severity_counts["low"],
            RISK_MEDIUM: severity_counts["medium"],
            RISK_HIGH: severity_counts["high"],
            RISK_CRITICAL: severity_counts["critical"],
        },
    }


def _severity_label(value: Any) -> str:
    risk = str(value or RISK_INFO).upper()
    if risk == RISK_CRITICAL:
        return "critical"
    if risk == RISK_HIGH:
        return "high"
    if risk == RISK_MEDIUM:
        return "medium"
    if risk == RISK_LOW:
        return "low"
    return "informational"


def _is_skipped_dict(finding: dict[str, Any]) -> bool:
    text = f"{finding.get('id', finding.get('check_id', ''))} {finding.get('title', '')} {finding.get('evidence', '')}".lower()
    return "skipped" in text or finding.get("metadata", {}).get("skipped") is True


def _grade_for_score(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"

from __future__ import annotations

from typing import Any

from websecscope.guide import recommendation_for
from websecscope.models import FAIL, PASS, WARNING, Finding, RISK_HIGH, RISK_INFO, RISK_LOW, RISK_MEDIUM, build_finding

RISKY_SERVICES = {
    "FTP": RISK_MEDIUM,
    "Telnet": RISK_HIGH,
    "Redis": RISK_HIGH,
    "MongoDB": RISK_HIGH,
    "MySQL/MariaDB": RISK_MEDIUM,
    "PostgreSQL": RISK_MEDIUM,
}


def analyze_services(version_detection: dict) -> list[Finding]:
    items = version_detection.get("items", [])
    findings: list[Finding] = []
    risky_items = [item for item in items if item.get("service") in RISKY_SERVICES]
    if risky_items:
        for item in risky_items:
            service = item.get("service", "unknown")
            findings.append(_finding(
                f"SERVICE_EXPOSED_{service.upper().replace('/', '_')}_{item.get('port')}",
                "service",
                f"Externally exposed service review: {service}",
                WARNING,
                RISKY_SERVICES[service],
                "A service commonly requiring strict network restriction is listening on the host.",
                _service_evidence(item),
                recommendation_for("SERVICE_RISKY_EXPOSURE"),
            ))
    else:
        findings.append(_finding(
            "SERVICE_RISKY_EXPOSURE_BASELINE",
            "service",
            "Risky service exposure baseline",
            PASS,
            RISK_INFO,
            "No FTP, Telnet, Redis, MongoDB, MySQL/MariaDB, or PostgreSQL listening service was identified.",
            _summary(items),
            "No action required.",
        ))

    ssh_findings = _analyze_ssh(items)
    findings.extend(ssh_findings)
    findings.append(_finding(
        "SERVICE_VERSION_INVENTORY",
        "service",
        "Service version inventory",
        PASS if _has_any_version(items) else WARNING,
        RISK_INFO if _has_any_version(items) else RISK_LOW,
        "Detected service banners were normalized into product/version fields for later CVE/CVSS lookup.",
        _version_summary(items),
        recommendation_for("SERVICE_VERSION_UNKNOWN") if not _has_any_version(items) else "No action required.",
    ))
    return findings


def _analyze_ssh(items: list[dict[str, Any]]) -> list[Finding]:
    findings = []
    for item in items:
        if item.get("service") != "SSH":
            continue
        banner = item.get("banner", "")
        if "protocol 1." in banner.lower() or "openssh_5." in banner.lower() or "openssh_6." in banner.lower():
            findings.append(_finding(
                f"SERVICE_SSH_VERSION_REVIEW_{item.get('port')}",
                "service",
                "SSH version review recommended",
                WARNING,
                RISK_MEDIUM,
                "SSH is not high risk by being open alone, but the observed banner suggests an older protocol or product generation.",
                _service_evidence(item),
                recommendation_for("SERVICE_SSH_REVIEW"),
            ))
    return findings


def _finding(
    check_id: str,
    category: str,
    title: str,
    status: str,
    risk: str,
    description: str,
    evidence: str,
    recommendation: str,
) -> Finding:
    return build_finding(check_id, category, title, status, risk, evidence, recommendation, description=description)


def _service_evidence(item: dict[str, Any]) -> str:
    normalized = item.get("normalized_service", {})
    return (
        f"port={item.get('port')}; protocol={item.get('protocol')}; service={item.get('service')}; "
        f"version={item.get('version')}; product={normalized.get('product')}; "
        f"banner={item.get('banner') or 'version not observed'}; confidence={item.get('confidence')}; "
        f"evidence={item.get('evidence')}"
    )


def _summary(items: list[dict[str, Any]]) -> str:
    if not items:
        return "No service items were available for analysis."
    return "; ".join(f"{item.get('port')}/{item.get('protocol')} {item.get('service')}" for item in items)


def _version_summary(items: list[dict[str, Any]]) -> str:
    if not items:
        return "No listening services available; version not observed."
    return "; ".join(
        f"{item.get('service')}:{item.get('detected_product', 'unknown')} {item.get('version', 'unknown')} on {item.get('port')}"
        for item in items
    )


def _has_any_version(items: list[dict[str, Any]]) -> bool:
    return any(item.get("version") not in {None, "", "unknown"} for item in items)

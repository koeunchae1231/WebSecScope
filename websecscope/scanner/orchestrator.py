from __future__ import annotations

from websecscope.analyzer.api_auth_analyzer import analyze_api_auth
from websecscope.analyzer.cve import analyze_cves
from websecscope.analyzer.docker_analyzer import analyze_docker_scan
from websecscope.analyzer.linux_analyzer import analyze_linux_scan
from websecscope.analyzer.service_analyzer import analyze_services
from websecscope.analyzer.score import calculate_score
from websecscope.models import ScanResult
from websecscope.scanner.api_scanner import scan_api_endpoints
from websecscope.scanner.auth_scanner import scan_auth_controls
from websecscope.scanner.docker_scanner import scan_docker_security
from websecscope.scanner.linux_scanner import scan_linux_security
from websecscope.scanner.service_detector import detect_services
from websecscope.scanner.version_detector import detect_versions
from websecscope.scanner.web import scan_web_target


def run_scan(
    target: str,
    include_api_auth: bool = True,
    include_linux: bool = True,
    include_docker: bool = True,
    include_service_detect: bool = True,
    include_cve: bool = True,
) -> ScanResult:
    findings = []
    findings.extend(scan_web_target(target))
    api_scan = {"enabled": False, "reason": "API/Auth analysis skipped by CLI option."}
    auth_scan = {"enabled": False, "reason": "API/Auth analysis skipped by CLI option."}
    linux_scan = {"status": "skipped", "reason": "Linux scan skipped by CLI option.", "evidence": ["Linux scan skipped by CLI option."]}
    docker_scan = {"status": "skipped", "reason": "Docker scan skipped by CLI option.", "evidence": ["Docker scan skipped by CLI option."], "containers": [], "images": []}
    service_detection = {"enabled": False, "reason": "Service detection skipped by CLI option.", "items": []}
    version_detection = {"enabled": False, "reason": "Service detection skipped by CLI option.", "items": []}
    cve_lookup = {"enabled": False, "reason": "CVE lookup skipped by CLI option.", "queries": [], "items": [], "errors": []}
    scanners = ["web"]
    if include_api_auth:
        api_scan = scan_api_endpoints(target)
        auth_scan = scan_auth_controls(target, api_scan)
        findings.extend(analyze_api_auth(api_scan, auth_scan))
        scanners.append("api_auth")
    if include_linux:
        linux_scan = scan_linux_security()
        findings.extend(analyze_linux_scan(linux_scan))
        scanners.append("linux")
    if include_service_detect:
        service_detection = detect_services()
        version_detection = detect_versions(service_detection)
        findings.extend(analyze_services(version_detection))
        scanners.append("service_detection")
    if include_docker:
        docker_scan = scan_docker_security()
        findings.extend(analyze_docker_scan(docker_scan))
        scanners.append("docker")
    cve_lookup, cve_findings = analyze_cves(findings, version_detection.get("items", []), enabled=include_cve)
    findings.extend(cve_findings)
    if include_cve:
        scanners.append("cve")
    score = calculate_score(findings)
    return ScanResult(
        target=target,
        findings=findings,
        score=score,
        metadata={"scanners": scanners},
        api_scan=api_scan,
        auth_scan=auth_scan,
        linux_scan=linux_scan,
        docker_scan=docker_scan,
        service_detection=service_detection,
        version_detection=version_detection,
        cve_lookup=cve_lookup,
    )

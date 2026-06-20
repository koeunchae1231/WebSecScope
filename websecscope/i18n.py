from __future__ import annotations

from typing import Any

SUPPORTED_LANGUAGES = {"ko", "en"}
DEFAULT_LANGUAGE = "ko"

SEVERITY_LABELS = {
    "ko": {
        "critical": "긴급",
        "high": "높음",
        "medium": "중간",
        "low": "낮음",
        "informational": "정보",
    },
    "en": {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "informational": "Informational",
    },
}

REPORT_TEXT = {
    "ko": {
        "title": "WebSecScope 보안 리포트",
        "executive_summary": "Executive Summary",
        "security_score": "Security Score",
        "grade": "Grade",
        "findings": "Findings",
        "effective_findings": "Effective Findings",
        "severity_summary": "Severity Summary",
        "top_risks": "Top Risks",
        "web_security": "Web Security",
        "api_auth_security": "API/Auth Security",
        "service_version": "Service & Version Detection",
        "cve_cvss": "CVE / CVSS",
        "linux_security": "Linux Security",
        "docker_security": "Docker Security",
        "all_findings": "All Findings",
        "finding_sections": "Findings by Category and OWASP",
        "status": "Status",
        "severity": "Severity",
        "severity_label": "Severity Label",
        "category": "Category",
        "owasp": "OWASP",
        "finding": "Finding",
        "description": "Description",
        "evidence": "Evidence",
        "interpretation": "Interpretation",
        "recommendation": "Recommendation",
        "no_findings": "No findings available for this section.",
        "no_top_risks": "No high-priority risks were identified.",
        "target": "Target",
        "generated": "Generated",
        "language": "Language",
        "before_after_ready": "Before/After comparison-ready report structure",
    },
    "en": {
        "title": "WebSecScope Security Report",
        "executive_summary": "Executive Summary",
        "security_score": "Security Score",
        "grade": "Grade",
        "findings": "Findings",
        "effective_findings": "Effective Findings",
        "severity_summary": "Severity Summary",
        "top_risks": "Top Risks",
        "web_security": "Web Security",
        "api_auth_security": "API/Auth Security",
        "service_version": "Service & Version Detection",
        "cve_cvss": "CVE / CVSS",
        "linux_security": "Linux Security",
        "docker_security": "Docker Security",
        "all_findings": "All Findings",
        "finding_sections": "Findings by Category and OWASP",
        "status": "Status",
        "severity": "Severity",
        "severity_label": "Severity Label",
        "category": "Category",
        "owasp": "OWASP",
        "finding": "Finding",
        "description": "Description",
        "evidence": "Evidence",
        "interpretation": "Interpretation",
        "recommendation": "Recommendation",
        "no_findings": "No findings available for this section.",
        "no_top_risks": "No high-priority risks were identified.",
        "target": "Target",
        "generated": "Generated",
        "language": "Language",
        "before_after_ready": "Before/After comparison-ready report structure",
    },
}

FINDING_TRANSLATIONS = {
    "ko": {
        "WEB_HEADER_CONTENT_SECURITY_POLICY": {
            "title": "Content-Security-Policy 헤더",
            "description": "CSP는 브라우저에서 허용되는 스크립트, 스타일, 리소스 출처를 제한해 XSS 영향을 줄입니다.",
            "recommendation": "웹 서버, 리버스 프록시 또는 애플리케이션에서 서비스에 맞는 Content-Security-Policy를 설정하세요.",
        },
        "WEB_HEADER_X_FRAME_OPTIONS": {
            "title": "X-Frame-Options 헤더",
            "description": "X-Frame-Options는 클릭재킹 방지를 위해 페이지가 frame/iframe에 로드되는 방식을 제한합니다.",
            "recommendation": "DENY 또는 SAMEORIGIN 정책을 설정하거나 CSP frame-ancestors를 함께 검토하세요.",
        },
        "WEB_SENSITIVE_PATHS": {
            "title": "민감 경로 노출 점검",
            "description": "저장소, 설정 파일, 백업, 관리자 후보 경로의 HTTP 응답 상태를 근거와 해석으로 분리해 평가합니다.",
            "recommendation": "관리자, 저장소, 백업, 설정 경로는 공개 접근을 차단하고 필요한 경우 인증 및 네트워크 제한을 적용하세요.",
        },
        "AUTH_MAY_BE_MISSING": {
            "title": "인증 누락 가능성",
            "description": "후보 API 경로가 인증 정보 없이 성공 응답을 반환했습니다.",
            "recommendation": "비공개 API에는 인증과 객체 단위 권한 검사를 적용하세요.",
        },
        "CVE_SERVICE_INVENTORY": {
            "title": "CVE/CVSS 분석 구조",
            "description": "CVE 조회는 탐지된 제품/버전 근거를 기반으로 하며 수동 검증 전에는 참고 정보입니다.",
            "recommendation": "서비스 배너 또는 패키지 인벤토리를 수집해 CVE 매칭 정확도를 높이세요.",
        },
    },
    "en": {},
}

RECOMMENDATION_TRANSLATIONS = {
    "ko": {
        "No action required.": "추가 조치가 필요하지 않습니다.",
        "Review the finding and apply the least-privilege secure configuration recommended by the service vendor.": "벤더 권장 보안 설정과 최소 권한 원칙에 맞춰 해당 항목을 검토하세요.",
        "Provide a fully qualified authorized URL.": "권한이 있는 완전한 URL(http:// 또는 https:// 포함)을 입력하세요.",
        "Verify network access, DNS, TLS settings, and that the target is authorized.": "네트워크 접근, DNS, TLS 설정, 진단 권한을 확인하세요.",
        "Run WebSecScope on the authorized Linux host to collect Linux security checks.": "권한이 있는 Linux 호스트에서 WebSecScope를 실행해 Linux 보안 점검을 수집하세요.",
        "Run WebSecScope on an authorized Docker host to collect container security checks.": "권한이 있는 Docker 호스트에서 WebSecScope를 실행해 컨테이너 보안 점검을 수집하세요.",
        "Collect service banners or package inventories to enable CVE matching.": "CVE 매칭을 위해 서비스 배너 또는 패키지 인벤토리를 수집하세요.",
    },
    "en": {},
}


def normalize_language(language: str | None) -> str:
    value = str(language or DEFAULT_LANGUAGE).lower()
    return value if value in SUPPORTED_LANGUAGES else DEFAULT_LANGUAGE


def text(key: str, language: str | None = None) -> str:
    lang = normalize_language(language)
    return REPORT_TEXT.get(lang, REPORT_TEXT[DEFAULT_LANGUAGE]).get(key, key)


def severity_label(severity: str, language: str | None = None) -> str:
    lang = normalize_language(language)
    normalized = str(severity or "informational").lower()
    return SEVERITY_LABELS.get(lang, SEVERITY_LABELS[DEFAULT_LANGUAGE]).get(normalized, normalized)


def localize_finding(payload: dict[str, Any], language: str | None = None) -> dict[str, Any]:
    lang = normalize_language(language)
    if lang == "en":
        payload["severity_label"] = severity_label(payload.get("severity"), lang)
        return payload

    check_id = str(payload.get("id") or payload.get("check_id") or "")
    translations = FINDING_TRANSLATIONS.get(lang, {})
    translation = translations.get(check_id) or _prefix_translation(translations, check_id)
    if translation:
        for key in ("title", "description", "recommendation"):
            if translation.get(key):
                payload[key] = translation[key]
    recommendation = str(payload.get("recommendation", ""))
    payload["recommendation"] = RECOMMENDATION_TRANSLATIONS.get(lang, {}).get(recommendation, recommendation)
    payload["severity_label"] = severity_label(payload.get("severity"), lang)
    return payload


def _prefix_translation(translations: dict[str, dict[str, str]], check_id: str) -> dict[str, str] | None:
    for key, value in translations.items():
        if check_id.startswith(key + "_"):
            return value
    return None

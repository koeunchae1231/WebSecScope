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
        "executive_summary": "요약",
        "security_score": "Security Score",
        "grade": "등급",
        "findings": "Findings",
        "effective_findings": "유효 Findings",
        "severity_summary": "Severity 요약",
        "top_risks": "주요 위험",
        "web_security": "Web Security",
        "api_auth_security": "API/Auth Security",
        "service_version": "Service & Version 탐지",
        "cve_cvss": "CVE / CVSS",
        "linux_security": "Linux Security",
        "docker_security": "Docker Security",
        "all_findings": "전체 Findings",
        "finding_sections": "Category 및 OWASP별 Findings",
        "status": "상태",
        "severity": "Severity",
        "severity_label": "Severity Label",
        "category": "Category",
        "owasp": "OWASP",
        "finding": "Finding",
        "description": "설명",
        "evidence": "Evidence",
        "interpretation": "해석",
        "recommendation": "개선 권고",
        "no_findings": "이 섹션에 표시할 Finding이 없습니다.",
        "no_top_risks": "우선순위가 높은 위험이 식별되지 않았습니다.",
        "target": "Target",
        "generated": "생성 시각",
        "language": "Language",
        "before_after_ready": "Before/After 비교 확장 가능 구조",
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
        "WEB_TARGET_URL": {
            "title": "Target URL 형식 오류",
            "description": "Target URL에 http:// 또는 https:// 스킴과 호스트가 포함되어야 합니다.",
        },
        "WEB_REACHABILITY": {
            "title": "Target 접근 실패",
            "description": "Target에 연결할 수 없어 Web 보안 검사를 완료하지 못했습니다.",
        },
        "WEB_HEADER_STRICT_TRANSPORT_SECURITY": {
            "title": "Strict-Transport-Security 헤더",
            "description": "HSTS는 브라우저가 HTTPS 연결을 우선 사용하도록 강제하여 다운그레이드 위험을 줄입니다.",
        },
        "WEB_HEADER_CONTENT_SECURITY_POLICY": {
            "title": "Content-Security-Policy 헤더",
            "description": "CSP는 브라우저에서 허용되는 스크립트, 스타일, 리소스 출처를 제한해 XSS 영향을 줄입니다.",
            "recommendation": (
                "Web 서버, reverse proxy, 또는 application 계층에서 서비스에 맞는 "
                "Content-Security-Policy를 설정하세요."
            ),
        },
        "WEB_HEADER_X_CONTENT_TYPE_OPTIONS": {
            "title": "X-Content-Type-Options 헤더",
            "description": "X-Content-Type-Options는 브라우저의 MIME sniffing으로 인한 오해석 위험을 줄입니다.",
        },
        "WEB_HEADER_X_FRAME_OPTIONS": {
            "title": "X-Frame-Options 헤더",
            "description": "X-Frame-Options는 clickjacking 방지를 위해 페이지의 frame/iframe 로드를 제한합니다.",
            "recommendation": "DENY 또는 SAMEORIGIN 정책을 설정하거나 CSP frame-ancestors 적용을 검토하세요.",
        },
        "WEB_HEADER_REFERRER_POLICY": {
            "title": "Referrer-Policy 헤더",
            "description": "Referrer-Policy는 외부 요청에 포함되는 referrer 정보 범위를 제한합니다.",
        },
        "WEB_HEADER_PERMISSIONS_POLICY": {
            "title": "Permissions-Policy 헤더",
            "description": "Permissions-Policy는 브라우저 기능과 민감 API 사용 범위를 제한합니다.",
        },
        "WEB_COOKIE_FLAGS": {
            "title": "Cookie 보안 속성",
            "description": "Secure, HttpOnly, SameSite 속성은 session cookie 탈취와 오용 위험을 줄입니다.",
        },
        "WEB_SENSITIVE_PATHS": {
            "title": "민감 경로 노출 점검",
            "description": (
                "저장소, 설정 파일, 백업, 관리자 정보 경로의 HTTP 응답 상태를 "
                "근거와 해석으로 분리해 평가합니다."
            ),
            "recommendation": (
                "관리자, 저장소, 백업, 설정 경로의 공개 접근을 차단하고 필요한 경우 "
                "인증 및 네트워크 제한을 적용하세요."
            ),
        },
        "AUTH_MAY_BE_MISSING": {
            "title": "인증 누락 가능성",
            "description": "정보 API 경로가 인증 정보 없이 성공 응답을 반환했습니다.",
            "recommendation": "비공개 API에는 인증과 객체 단위 권한 검사를 적용하세요.",
        },
        "AUTH_PROTECTED": {
            "title": "API 경로 보호 확인",
            "description": "인증되지 않은 요청이 authorization 관련 상태로 거부되었습니다.",
        },
        "AUTH_COOKIE_ATTRIBUTES": {
            "title": "인증 Cookie 보안 속성",
            "description": "Set-Cookie header의 SameSite, HttpOnly, Secure 속성을 점검했습니다.",
        },
        "JWT_USAGE_NOT_OBSERVED": {
            "title": "JWT 사용 미관찰",
            "description": "응답 header, cookie, 짧은 응답 sample에서 JWT 형태의 token pattern이 관찰되지 않았습니다.",
        },
        "JWT_STATIC_STRUCTURE_REVIEW": {
            "title": "JWT 정적 구조 검토",
            "description": "JWT 형태의 token은 서명 검증 없이 구조 검토 목적으로만 decode되었습니다.",
        },
        "CORS_BASELINE": {
            "title": "CORS 기준 점검",
            "description": "wildcard, credentialed wildcard, origin reflection CORS pattern이 관찰되지 않았습니다.",
        },
        "RATE_LIMIT_HEADERS": {
            "title": "Rate limit header 관찰",
            "description": "Login 및 authentication 후보 endpoint에서 rate-limit response header를 1회 점검했습니다.",
        },
        "CVE_SERVICE_INVENTORY": {
            "title": "CVE/CVSS 분석 구조",
            "description": "CVE 조회는 탐지된 제품/버전 근거를 기반으로 하며 수동 검증 전에는 참고 정보입니다.",
            "recommendation": "서비스 banner 또는 package inventory를 수집해 CVE 매칭 정확도를 높이세요.",
        },
    },
    "en": {},
}

RECOMMENDATION_TRANSLATIONS = {
    "ko": {
        "No action required.": "추가 조치가 필요하지 않습니다.",
        "Review the finding and apply the least-privilege secure configuration recommended by the service vendor.": (
            "서비스 vendor 권장 보안 설정과 최소 권한 원칙에 맞춰 해당 Finding을 검토하세요."
        ),
        "Provide a fully qualified authorized URL.": "권한이 있는 전체 URL(http:// 또는 https:// 포함)을 입력하세요.",
        "Verify network access, DNS, TLS settings, and that the target is authorized.": (
            "네트워크 접근, DNS, TLS 설정, 진단 권한을 확인하세요."
        ),
        "Add the missing HTTP security header at the web server, reverse proxy, or application layer.": (
            "Web server, reverse proxy, 또는 application 계층에 누락된 HTTP 보안 헤더를 추가하세요."
        ),
        "Set Secure, HttpOnly, and SameSite attributes on session and sensitive cookies.": (
            "Session 및 민감 cookie에 Secure, HttpOnly, SameSite 속성을 설정하세요."
        ),
        "Remove public exposure for administrative, repository, backup, and configuration paths.": (
            "관리자, repository, backup, configuration 경로가 외부에 공개되지 않도록 차단하세요."
        ),
        "Run WebSecScope on the authorized Linux host to collect Linux security checks.": (
            "권한이 있는 Linux host에서 WebSecScope를 실행해 Linux 보안 점검을 수집하세요."
        ),
        "Run WebSecScope on an authorized Docker host to collect container security checks.": (
            "권한이 있는 Docker host에서 WebSecScope를 실행해 container 보안 점검을 수집하세요."
        ),
        "Collect service banners or package inventories to enable CVE matching.": (
            "CVE 매칭을 위해 service banner 또는 package inventory를 수집하세요."
        ),
        "Review service versions against vendor advisories and patch vulnerable packages promptly.": (
            "서비스 버전을 vendor advisory와 대조하고 취약한 package를 우선 패치하세요."
        ),
        "Verify whether the detected product/version and deployment configuration are affected, then prioritize vendor patches or mitigations by CVSS severity.": (
            "탐지된 제품/버전과 배포 구성이 영향을 받는지 확인한 뒤 CVSS severity에 따라 patch 또는 완화 조치를 우선순위화하세요."
        ),
        "Apply rate limiting to authentication endpoints and expose standard retry or rate-limit headers where appropriate.": (
            "인증 endpoint에 rate limiting을 적용하고 필요한 경우 표준 retry 또는 rate-limit header를 노출하세요."
        ),
        "Require authentication and object-level authorization for non-public API endpoints.": (
            "비공개 API endpoint에는 인증과 객체 단위 authorization을 적용하세요."
        ),
        "Review CORS origin and credential policy against a strict allowlist.": (
            "CORS origin 및 credential 정책을 엄격한 allowlist 기준으로 검토하세요."
        ),
        "Review JWT signing, expiration, and payload content.": (
            "JWT signing, expiration, payload 내용을 검토하세요."
        ),
    },
    "en": {},
}

INTERPRETATION_TRANSLATIONS = {
    "ko": {
        "Target URL is invalid": "Target URL 형식이 올바르지 않습니다.",
        "Target was not reachable": "Target에 접근할 수 없습니다.",
        "Cookie security attributes": "Cookie 보안 속성을 확인한 결과입니다.",
        "Strict-Transport-Security header": "Strict-Transport-Security 헤더를 확인한 결과입니다.",
        "Content-Security-Policy header": "Content-Security-Policy 헤더를 확인한 결과입니다.",
        "X-Content-Type-Options header": "X-Content-Type-Options 헤더를 확인한 결과입니다.",
        "X-Frame-Options header": "X-Frame-Options 헤더를 확인한 결과입니다.",
        "Referrer-Policy header": "Referrer-Policy 헤더를 확인한 결과입니다.",
        "Permissions-Policy header": "Permissions-Policy 헤더를 확인한 결과입니다.",
        "Authentication cookie attributes": "인증 Cookie 보안 속성을 확인한 결과입니다.",
        "JWT usage not observed": "JWT 사용이 관찰되지 않았습니다.",
        "Rate limit header observation": "Rate limit header를 관찰한 결과입니다.",
        "API path appears protected": "API 경로가 보호되고 있는 것으로 보입니다.",
        "No Set-Cookie headers were observed.": "Set-Cookie header가 관찰되지 않았습니다.",
        "All observed cookies include Secure, HttpOnly, and SameSite.": (
            "관찰된 모든 cookie에 Secure, HttpOnly, SameSite 속성이 포함되어 있습니다."
        ),
        "Observed Set-Cookie headers were checked for SameSite, HttpOnly, and Secure attributes.": (
            "Set-Cookie header의 SameSite, HttpOnly, Secure 속성을 확인했습니다."
        ),
        "No Set-Cookie headers observed on API/Auth candidates.": (
            "API/Auth 후보에서 Set-Cookie header가 관찰되지 않았습니다."
        ),
        "No JWT-like token pattern was observed in response headers, cookies, or small response samples.": (
            "응답 header, cookie, 짧은 응답 sample에서 JWT 형태의 token pattern이 관찰되지 않았습니다."
        ),
        "No CORS response headers observed on API candidates.": (
            "API 후보에서 CORS response header가 관찰되지 않았습니다."
        ),
        "Login and authentication candidates were checked once for rate-limit response headers.": (
            "Login 및 authentication 후보 endpoint에서 rate-limit response header를 1회 점검했습니다."
        ),
        "Sensitive path exposure": "민감 경로 노출 가능성을 확인한 결과입니다.",
        "No sensitive path signal was observed.": "민감 경로 신호가 관찰되지 않았습니다.",
        "Sensitive path probes distinguish exposed, protected, redirected, not found, and server error responses.": (
            "민감 경로 probe는 노출, 보호됨, redirect, not found, server error 응답을 구분합니다."
        ),
        "HTTP 200 indicates a sensitive path may be directly exposed.": (
            "HTTP 200은 민감 경로가 직접 노출되었을 가능성을 의미합니다."
        ),
        "HTTP 401/403 indicates the path may exist but is protected; this is evidence for review, not a confirmed exposure.": (
            "HTTP 401/403은 경로가 존재하지만 보호되고 있을 가능성을 의미하며, 확정 노출이 아니라 검토 근거입니다."
        ),
        "HTTP 301/302 indicates redirection; review the Location target and whether redirects are intended.": (
            "HTTP 301/302는 redirect를 의미하므로 Location 대상과 의도된 redirect인지 검토하세요."
        ),
        "HTTP 404 indicates the tested path was not found.": "HTTP 404는 테스트한 경로를 찾을 수 없음을 의미합니다.",
        "HTTP 500 indicates the probe triggered a server error and should be reviewed as a stability or information-disclosure risk.": (
            "HTTP 500은 probe가 server error를 유발했음을 의미하므로 안정성 또는 정보 노출 위험으로 검토하세요."
        ),
        "CVE lookup is based on detected product/version evidence and remains advisory until manually verified.": (
            "CVE 조회는 탐지된 제품/버전 근거를 기반으로 하며 수동 검증 전에는 참고 정보입니다."
        ),
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
    return SEVERITY_LABELS.get(lang, SEVERITY_LABELS[DEFAULT_LANGUAGE]).get(
        normalized,
        normalized,
    )


def localize_finding(
    payload: dict[str, Any],
    language: str | None = None,
) -> dict[str, Any]:
    lang = normalize_language(language)
    if lang == "en":
        payload["severity_label"] = severity_label(payload.get("severity"), lang)
        return payload

    check_id = str(payload.get("id") or payload.get("check_id") or "")
    translation = _translation_for(FINDING_TRANSLATIONS.get(lang, {}), check_id)
    original_title = str(payload.get("title", ""))
    original_interpretation = str(payload.get("interpretation", ""))
    if translation:
        for key in ("title", "description", "recommendation"):
            if translation.get(key):
                payload[key] = translation[key]
        if original_interpretation == original_title and translation.get("description"):
            payload["interpretation"] = translation["description"]

    recommendation = str(payload.get("recommendation", ""))
    payload["recommendation"] = RECOMMENDATION_TRANSLATIONS.get(lang, {}).get(
        recommendation,
        recommendation,
    )

    interpretation = str(payload.get("interpretation", ""))
    payload["interpretation"] = _translate_interpretation(interpretation, lang)
    payload["severity_label"] = severity_label(payload.get("severity"), lang)
    return payload


def _translation_for(
    translations: dict[str, dict[str, str]],
    check_id: str,
) -> dict[str, str] | None:
    if check_id in translations:
        return translations[check_id]
    for key, value in translations.items():
        if check_id.startswith(key + "_"):
            return value
    return None


def _translate_interpretation(interpretation: str, language: str) -> str:
    translations = INTERPRETATION_TRANSLATIONS.get(language, {})
    if interpretation in translations:
        return translations[interpretation]

    translated = interpretation
    for english, localized in translations.items():
        translated = translated.replace(english, localized)
    return translated

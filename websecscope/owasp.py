from __future__ import annotations

DEFAULT_OWASP_CATEGORY = "A05 Security Misconfiguration"

OWASP_BY_CATEGORY = {
    "web": "A05 Security Misconfiguration",
    "service": "A05 Security Misconfiguration",
    "linux": "A05 Security Misconfiguration",
    "docker": "A05 Security Misconfiguration",
    "api": "A01 Broken Access Control",
    "auth": "A07 Identification and Authentication Failures",
    "jwt": "A07 Identification and Authentication Failures",
    "cors": "A05 Security Misconfiguration",
    "idor": "A01 Broken Access Control",
    "rate_limit": "A07 Identification and Authentication Failures",
    "cve": "A06 Vulnerable and Outdated Components",
}

OWASP_BY_CHECK_PREFIX = {
    "WEB_HEADER_CONTENT_SECURITY_POLICY": "A05 Security Misconfiguration",
    "WEB_HEADER_X_FRAME_OPTIONS": "A05 Security Misconfiguration",
    "WEB_SENSITIVE_PATHS": "A05 Security Misconfiguration",
    "AUTH_": "A07 Identification and Authentication Failures",
    "JWT_": "A07 Identification and Authentication Failures",
    "CVE_": "A06 Vulnerable and Outdated Components",
    "DOCKER_IMAGE_TAG": "A06 Vulnerable and Outdated Components",
    "DOCKER_DIGEST_PINNING": "A06 Vulnerable and Outdated Components",
}


def owasp_category_for(check_id: str, category: str) -> str:
    for prefix, owasp_category in OWASP_BY_CHECK_PREFIX.items():
        if check_id.startswith(prefix):
            return owasp_category
    return OWASP_BY_CATEGORY.get(category, DEFAULT_OWASP_CATEGORY)

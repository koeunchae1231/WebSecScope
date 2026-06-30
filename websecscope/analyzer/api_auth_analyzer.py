from __future__ import annotations

import base64
import json
import re
from datetime import datetime, timezone
from typing import Any

from websecscope.guide import recommendation_for
from websecscope.models import FAIL, PASS, WARNING, Finding, RISK_HIGH, RISK_INFO, RISK_LOW, RISK_MEDIUM, build_finding

SUCCESS_STATUSES = {200, 201, 202, 204}
PROTECTED_STATUSES = {401, 403}
SENSITIVE_DOC_PATHS = {"/swagger", "/api-docs", "/openapi.json"}
ADMIN_PATH_MARKERS = ("admin",)
IDOR_PATTERN = re.compile(r"/(?:api/)?(?:users?|orders?|patients?)/\d+(?:/|$)", re.IGNORECASE)
JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\b")
SENSITIVE_JWT_KEYS = {"email", "phone", "password", "passwd", "ssn", "token", "secret", "api_key"}
LONG_EXP_SECONDS = 60 * 60 * 24 * 365


def analyze_api_auth(api_scan: dict, auth_scan: dict) -> list[Finding]:
    endpoints = api_scan.get("endpoints", [])
    auth_paths = auth_scan.get("auth_paths", [])
    findings: list[Finding] = []
    findings.extend(_analyze_endpoint_exposure(endpoints))
    findings.extend(_analyze_auth_access(endpoints))
    findings.extend(_analyze_cookie_security(endpoints))
    findings.extend(_analyze_jwt_usage(endpoints))
    findings.extend(_analyze_cors(endpoints))
    findings.extend(_analyze_idor_patterns(endpoints))
    findings.extend(_analyze_rate_limit_headers(auth_paths))
    return findings


def _analyze_endpoint_exposure(endpoints: list[dict[str, Any]]) -> list[Finding]:
    exposed_docs = []
    exposed_admin = []
    for endpoint in endpoints:
        path = endpoint.get("path", "")
        status = endpoint.get("status_code")
        if status in SUCCESS_STATUSES and path in SENSITIVE_DOC_PATHS:
            exposed_docs.append(_endpoint_evidence(endpoint))
        if status in SUCCESS_STATUSES and any(marker in path.lower() for marker in ADMIN_PATH_MARKERS):
            exposed_admin.append(_endpoint_evidence(endpoint))

    findings = []
    if exposed_docs:
        findings.append(_finding(
            "API_DOCS_EXPOSED",
            "api",
            "Sensitive API documentation may be exposed",
            FAIL,
            RISK_MEDIUM,
            "Publicly reachable API documentation can disclose routes, schemas, and authentication assumptions.",
            "; ".join(exposed_docs),
            recommendation_for("API_DOCS_EXPOSED"),
        ))
    if exposed_admin:
        findings.append(_finding(
            "API_ADMIN_PATH_EXPOSED",
            "api",
            "Administrative API path may be exposed",
            FAIL,
            RISK_HIGH,
            "An administrative path returned a success status without authentication context.",
            "; ".join(exposed_admin),
            recommendation_for("API_ADMIN_PATH_EXPOSED"),
        ))
    if not findings:
        findings.append(_finding(
            "API_ENDPOINT_EXPOSURE",
            "api",
            "API exposure baseline",
            PASS,
            RISK_INFO,
            "No sensitive API documentation or administrative candidate returned a success status.",
            _summarize_statuses(endpoints),
            "No action required.",
        ))
    return findings


def _analyze_auth_access(endpoints: list[dict[str, Any]]) -> list[Finding]:
    findings = []
    for endpoint in endpoints:
        path = endpoint.get("path", "")
        if not _is_api_or_admin_path(path):
            continue
        status = endpoint.get("status_code")
        if status in SUCCESS_STATUSES:
            findings.append(_finding(
                f"AUTH_MAY_BE_MISSING_{_id_part(path)}",
                "auth",
                "Authentication may be missing",
                WARNING,
                RISK_MEDIUM,
                "A candidate API path returned a success status without an Authorization header.",
                _endpoint_evidence(endpoint),
                recommendation_for("AUTH_MAY_BE_MISSING"),
            ))
        elif status in PROTECTED_STATUSES:
            findings.append(_finding(
                f"AUTH_PROTECTED_{_id_part(path)}",
                "auth",
                "API path appears protected",
                PASS,
                RISK_INFO,
                "The unauthenticated request was rejected with an authorization-related status.",
                _endpoint_evidence(endpoint),
                "No action required.",
            ))
    return findings


def _analyze_cookie_security(endpoints: list[dict[str, Any]]) -> list[Finding]:
    weak = []
    protected = []
    for endpoint in endpoints:
        for cookie in endpoint.get("set_cookie", []):
            lower_cookie = cookie.lower()
            missing = [flag for flag in ("samesite", "httponly", "secure") if flag not in lower_cookie]
            if missing:
                weak.append(f"{endpoint.get('path')}: {cookie.split(';', 1)[0]} missing {', '.join(missing)}")
            else:
                protected.append(endpoint.get("path"))
    return [
        _finding(
            "AUTH_COOKIE_ATTRIBUTES",
            "auth",
            "Authentication cookie attributes",
            FAIL if weak else PASS,
            RISK_MEDIUM if weak else RISK_INFO,
            "Observed Set-Cookie headers were checked for SameSite, HttpOnly, and Secure attributes.",
            "; ".join(weak) if weak else f"Protected cookie attributes observed on {len(set(protected))} path(s)." if protected else "No Set-Cookie headers observed on API/Auth candidates.",
            recommendation_for("WEB_COOKIE_FLAGS") if weak else "No action required.",
        )
    ]


def _analyze_jwt_usage(endpoints: list[dict[str, Any]]) -> list[Finding]:
    decoded_tokens = []
    issues = []
    for endpoint in endpoints:
        sources = list(endpoint.get("set_cookie", []))
        sources.extend(str(value) for value in endpoint.get("headers", {}).values())
        sources.append(endpoint.get("body_sample", ""))
        for source in sources:
            for token in JWT_PATTERN.findall(source or ""):
                decoded = _decode_jwt(token)
                if not decoded:
                    continue
                decoded["path"] = endpoint.get("path")
                decoded_tokens.append(decoded)
                issues.extend(_jwt_issues(decoded))

    if not decoded_tokens:
        return [_finding(
            "JWT_USAGE_NOT_OBSERVED",
            "jwt",
            "JWT usage not observed",
            PASS,
            RISK_INFO,
            "No JWT-like token pattern was observed in response headers, cookies, or small response samples.",
            "No JWT-like token found.",
            "No action required.",
        )]

    return [_finding(
        "JWT_STATIC_STRUCTURE_REVIEW",
        "jwt",
        "JWT static structure review",
        WARNING if issues else PASS,
        RISK_MEDIUM if issues else RISK_INFO,
        "JWT-like tokens were decoded without signature verification for structural review only.",
        "; ".join(issues) if issues else f"{len(decoded_tokens)} JWT-like token(s) decoded; no structural issue observed.",
        recommendation_for("JWT_REVIEW") if issues else "No action required.",
        {"tokens": [_safe_jwt_metadata(token) for token in decoded_tokens]},
    )]


def _analyze_cors(endpoints: list[dict[str, Any]]) -> list[Finding]:
    findings = []
    for endpoint in endpoints:
        cors = endpoint.get("cors", {})
        origin = (cors.get("access_control_allow_origin") or "").strip()
        credentials = (cors.get("access_control_allow_credentials") or "").strip().lower()
        if origin == "*" and credentials == "true":
            findings.append(_finding(
                f"CORS_WILDCARD_WITH_CREDENTIALS_{_id_part(endpoint.get('path', 'root'))}",
                "cors",
                "CORS wildcard origin allows credentials",
                FAIL,
                RISK_HIGH,
                "Access-Control-Allow-Origin: * combined with credentials can expose authenticated browser requests.",
                _cors_evidence(endpoint),
                recommendation_for("CORS_WILDCARD_CREDENTIALS"),
            ))
        elif cors.get("origin_reflection_observed"):
            findings.append(_finding(
                f"CORS_ORIGIN_REFLECTION_{_id_part(endpoint.get('path', 'root'))}",
                "cors",
                "CORS origin reflection suspected",
                WARNING,
                RISK_MEDIUM,
                "The response reflected a test Origin header in Access-Control-Allow-Origin.",
                _cors_evidence(endpoint),
                recommendation_for("CORS_ORIGIN_REFLECTION"),
            ))
        elif origin == "*":
            findings.append(_finding(
                f"CORS_WILDCARD_{_id_part(endpoint.get('path', 'root'))}",
                "cors",
                "CORS wildcard origin observed",
                WARNING,
                RISK_LOW,
                "Wildcard CORS may be acceptable for public APIs but should be reviewed.",
                _cors_evidence(endpoint),
                recommendation_for("CORS_WILDCARD"),
            ))
    if not findings:
        findings.append(_finding(
            "CORS_BASELINE",
            "cors",
            "CORS baseline",
            PASS,
            RISK_INFO,
            "No wildcard, credentialed wildcard, or origin-reflection CORS pattern was observed.",
            _summarize_cors(endpoints),
            "No action required.",
        ))
    return findings


def _analyze_idor_patterns(endpoints: list[dict[str, Any]]) -> list[Finding]:
    candidates = [endpoint.get("path", "") for endpoint in endpoints if IDOR_PATTERN.search(endpoint.get("path", ""))]
    return [_finding(
        "IDOR_PATTERN_REVIEW",
        "idor",
        "IDOR review recommended",
        WARNING if candidates else PASS,
        RISK_LOW if candidates else RISK_INFO,
        "Numeric object identifiers in URLs are a review signal only and do not confirm an IDOR vulnerability.",
        f"Numeric ID path pattern(s): {', '.join(candidates)}" if candidates else "No numeric object ID candidate paths were observed.",
        recommendation_for("IDOR_REVIEW") if candidates else "No action required.",
    )]


def _analyze_rate_limit_headers(auth_paths: list[dict[str, Any]]) -> list[Finding]:
    evidence = []
    missing = []
    for endpoint in auth_paths:
        headers = {key.lower(): value for key, value in endpoint.get("headers", {}).items()}
        observed = {key: value for key, value in headers.items() if key.startswith("x-ratelimit") or key == "retry-after"}
        if observed:
            evidence.append(f"{endpoint.get('path')}: {observed}")
        else:
            missing.append(endpoint.get("path"))
    return [_finding(
        "RATE_LIMIT_HEADERS",
        "rate_limit",
        "Rate limit header observation",
        WARNING if missing else PASS,
        RISK_LOW if missing else RISK_INFO,
        "Login and authentication candidates were checked once for rate-limit response headers.",
        "; ".join(evidence) if evidence else f"Rate limit header not observed on: {', '.join(missing)}" if missing else "No login/auth candidate paths were reachable for header observation.",
        recommendation_for("RATE_LIMIT_HEADERS") if missing else "No action required.",
    )]


def _decode_jwt(token: str) -> dict[str, Any] | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_base64url_decode(parts[0]))
        payload = json.loads(_base64url_decode(parts[1]))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    return {"header": header, "payload": payload}


def _base64url_decode(value: str) -> str:
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")


def _jwt_issues(decoded: dict[str, Any]) -> list[str]:
    issues = []
    header = decoded.get("header", {})
    payload = decoded.get("payload", {})
    path = decoded.get("path")
    if str(header.get("alg", "")).lower() == "none":
        issues.append(f"{path}: JWT alg none observed")
    exp = payload.get("exp")
    if exp is None:
        issues.append(f"{path}: JWT exp claim missing")
    elif isinstance(exp, int):
        now = int(datetime.now(timezone.utc).timestamp())
        if exp - now > LONG_EXP_SECONDS:
            issues.append(f"{path}: JWT exp is more than one year in the future")
    sensitive_keys = sorted(SENSITIVE_JWT_KEYS & set(str(key).lower() for key in payload.keys()))
    if sensitive_keys:
        issues.append(f"{path}: JWT payload contains sensitive-looking key(s): {', '.join(sensitive_keys)}")
    return issues


def _safe_jwt_metadata(decoded: dict[str, Any]) -> dict[str, Any]:
    payload = decoded.get("payload", {})
    return {
        "path": decoded.get("path"),
        "alg": decoded.get("header", {}).get("alg"),
        "payload_keys": sorted(payload.keys()),
        "has_exp": "exp" in payload,
    }


def _finding(
    check_id: str,
    category: str,
    title: str,
    status: str,
    risk: str,
    description: str,
    evidence: str,
    recommendation: str,
    metadata: dict[str, Any] | None = None,
) -> Finding:
    return build_finding(
        check_id,
        category,
        title,
        status,
        risk,
        evidence,
        recommendation,
        description=description,
        metadata=metadata,
    )


def _endpoint_evidence(endpoint: dict[str, Any]) -> str:
    cors = endpoint.get("cors", {})
    return (
        f"{endpoint.get('path')} returned HTTP {endpoint.get('status_code')}; "
        f"Content-Type={endpoint.get('content_type')}; Server={endpoint.get('server')}; "
        f"ACAO={cors.get('access_control_allow_origin')}; "
        f"ACAC={cors.get('access_control_allow_credentials')}; "
        f"WWW-Authenticate={endpoint.get('www_authenticate')}"
    )


def _cors_evidence(endpoint: dict[str, Any]) -> str:
    cors = endpoint.get("cors", {})
    return (
        f"{endpoint.get('path')}: ACAO={cors.get('access_control_allow_origin')}; "
        f"ACAC={cors.get('access_control_allow_credentials')}; "
        f"ACAM={cors.get('access_control_allow_methods')}; "
        f"ACAH={cors.get('access_control_allow_headers')}; "
        f"origin_reflection={cors.get('origin_reflection_observed')}"
    )


def _summarize_statuses(endpoints: list[dict[str, Any]]) -> str:
    return "; ".join(f"{endpoint.get('path')}={endpoint.get('status_code')}" for endpoint in endpoints)


def _summarize_cors(endpoints: list[dict[str, Any]]) -> str:
    values = []
    for endpoint in endpoints:
        cors = endpoint.get("cors", {})
        if any(cors.get(key) for key in cors):
            values.append(_cors_evidence(endpoint))
    return "; ".join(values) if values else "No CORS response headers observed on API candidates."


def _is_api_or_admin_path(path: str) -> bool:
    lower_path = path.lower()
    return lower_path.startswith("/api") or "admin" in lower_path


def _id_part(path: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", path.strip("/")).strip("_").upper() or "ROOT"

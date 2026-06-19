from __future__ import annotations

import socket
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

from websecscope.guide import recommendation_for
from websecscope.models import FAIL, PASS, WARNING, Finding, RISK_HIGH, RISK_INFO, RISK_LOW, RISK_MEDIUM

SECURITY_HEADERS = {
    "strict-transport-security": ("Strict-Transport-Security", RISK_HIGH),
    "content-security-policy": ("Content-Security-Policy", RISK_HIGH),
    "x-content-type-options": ("X-Content-Type-Options", RISK_MEDIUM),
    "x-frame-options": ("X-Frame-Options", RISK_MEDIUM),
    "referrer-policy": ("Referrer-Policy", RISK_LOW),
    "permissions-policy": ("Permissions-Policy", RISK_LOW),
}

SENSITIVE_PATHS = [".git/HEAD", ".env", "backup.zip", "admin", "phpinfo.php"]
HTTP_TIMEOUT_SECONDS = 1
socket.setdefaulttimeout(HTTP_TIMEOUT_SECONDS)


def scan_web_target(target: str) -> list[Finding]:
    findings: list[Finding] = []
    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return [
            Finding(
                check_id="WEB_TARGET_URL",
                category="web",
                title="Target URL is invalid",
                status=WARNING,
                risk=RISK_LOW,
                evidence=f"Target must include http:// or https://: {target}",
                recommendation="Provide a fully qualified authorized URL.",
            )
        ]

    response = _request(target, method="HEAD")
    if response["error"]:
        response = _request(target, method="GET")
    if response["error"]:
        return [
            Finding(
                check_id="WEB_REACHABILITY",
                category="web",
                title="Target was not reachable",
                status=WARNING,
                risk=RISK_MEDIUM,
                evidence=response["error"],
                recommendation="Verify network access, DNS, TLS settings, and that the target is authorized.",
            )
        ]

    headers = {key.lower(): value for key, value in response["headers"].items()}
    findings.extend(_scan_security_headers(headers))
    findings.extend(_scan_cookie_flags(response["headers"].get_all("Set-Cookie", []) if hasattr(response["headers"], "get_all") else []))
    findings.extend(_scan_sensitive_paths(target))
    return findings


def _request(url: str, method: str = "HEAD") -> dict:
    request = Request(url, method=method, headers={"User-Agent": "WebSecScope/1.0"})
    try:
        with urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            return {
                "status": response.status,
                "headers": response.headers,
                "error": None,
            }
    except HTTPError as exc:
        return {"status": exc.code, "headers": exc.headers, "error": None}
    except (HTTPException, TimeoutError, URLError, OSError) as exc:
        return {"status": None, "headers": {}, "error": f"{type(exc).__name__}: request failed"}


def _scan_security_headers(headers: dict[str, str]) -> list[Finding]:
    findings: list[Finding] = []
    for header_key, (header_name, risk) in SECURITY_HEADERS.items():
        present = header_key in headers and bool(headers[header_key].strip())
        findings.append(
            Finding(
                check_id=f"WEB_HEADER_{header_name.upper().replace('-', '_')}",
                category="web",
                title=f"{header_name} header",
                status=PASS if present else FAIL,
                risk=RISK_INFO if present else risk,
                evidence=f"{header_name}: {headers.get(header_key)}" if present else f"{header_name} is missing",
                recommendation="No action required." if present else recommendation_for("WEB_HEADER_MISSING"),
            )
        )
    return findings


def _scan_cookie_flags(cookies: list[str]) -> list[Finding]:
    if not cookies:
        return [
            Finding(
                check_id="WEB_COOKIE_FLAGS",
                category="web",
                title="Cookie security attributes",
                status=PASS,
                risk=RISK_INFO,
                evidence="No Set-Cookie headers were observed.",
                recommendation="No action required.",
            )
        ]

    weak_cookies = []
    for cookie in cookies:
        lower_cookie = cookie.lower()
        missing = [flag for flag in ["secure", "httponly", "samesite"] if flag not in lower_cookie]
        if missing:
            weak_cookies.append(f"{cookie.split(';', 1)[0]} missing {', '.join(missing)}")

    return [
        Finding(
            check_id="WEB_COOKIE_FLAGS",
            category="web",
            title="Cookie security attributes",
            status=FAIL if weak_cookies else PASS,
            risk=RISK_MEDIUM if weak_cookies else RISK_INFO,
            evidence="; ".join(weak_cookies) if weak_cookies else "All observed cookies include Secure, HttpOnly, and SameSite.",
            recommendation=recommendation_for("WEB_COOKIE_FLAGS") if weak_cookies else "No action required.",
        )
    ]


def _scan_sensitive_paths(target: str) -> list[Finding]:
    exposed = []
    for path in SENSITIVE_PATHS:
        probe_url = urljoin(target.rstrip("/") + "/", path)
        response = _request(probe_url, method="HEAD")
        if response["error"]:
            continue
        if response["status"] in {200, 206, 301, 302, 401, 403}:
            exposed.append(f"{path} returned HTTP {response['status']}")

    return [
        Finding(
            check_id="WEB_SENSITIVE_PATHS",
            category="web",
            title="Sensitive path exposure",
            status=FAIL if exposed else PASS,
            risk=RISK_HIGH if exposed else RISK_INFO,
            evidence="; ".join(exposed) if exposed else "No common sensitive paths responded as exposed.",
            recommendation=recommendation_for("WEB_SENSITIVE_PATH") if exposed else "No action required.",
        )
    ]

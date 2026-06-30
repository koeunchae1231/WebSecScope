from __future__ import annotations

import socket
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from websecscope.guide import recommendation_for
from websecscope.models import FAIL, PASS, WARNING, Finding, RISK_HIGH, RISK_INFO, RISK_LOW, RISK_MEDIUM
from websecscope.rules.web import SECURITY_HEADERS, SENSITIVE_PATHS

HTTP_TIMEOUT_SECONDS = 1
socket.setdefaulttimeout(HTTP_TIMEOUT_SECONDS)


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


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


def _request(url: str, method: str = "HEAD", follow_redirects: bool = True) -> dict:
    request = Request(url, method=method, headers={"User-Agent": "WebSecScope/1.0"})
    try:
        opener = build_opener() if follow_redirects else build_opener(_NoRedirectHandler)
        with opener.open(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            return {
                "status": response.status,
                "headers": response.headers,
                "location": response.headers.get("Location"),
                "error": None,
            }
    except HTTPError as exc:
        return {"status": exc.code, "headers": exc.headers, "location": exc.headers.get("Location"), "error": None}
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
    observations = []
    risk_statuses = set()
    for path in SENSITIVE_PATHS:
        probe_url = urljoin(target.rstrip("/") + "/", path)
        response = _request(probe_url, method="HEAD", follow_redirects=False)
        if response["error"]:
            continue
        status = response["status"]
        if status in {200, 301, 302, 401, 403, 404, 500}:
            observations.append(_sensitive_path_observation(path, response))
            risk_statuses.add(status)

    exposed = any(status == 200 for status in risk_statuses)
    protected_exists = any(status in {401, 403} for status in risk_statuses)
    redirected = any(status in {301, 302} for status in risk_statuses)
    server_error = 500 in risk_statuses
    risky = exposed or server_error
    review = protected_exists or redirected

    return [
        Finding(
            check_id="WEB_SENSITIVE_PATHS",
            category="web",
            title="Sensitive path exposure",
            status=FAIL if risky else WARNING if review else PASS,
            risk=RISK_HIGH if exposed else RISK_MEDIUM if server_error else RISK_LOW if review else RISK_INFO,
            evidence="; ".join(observations) if observations else "No common sensitive paths responded as exposed.",
            recommendation=recommendation_for("WEB_SENSITIVE_PATH") if exposed else "No action required.",
            metadata={
                "description": "Sensitive path probes distinguish exposed, protected, redirected, not found, and server error responses.",
                "interpretation": _sensitive_path_interpretation(risk_statuses),
                "http_statuses": sorted(status for status in risk_statuses if status is not None),
            },
        )
    ]


def _sensitive_path_observation(path: str, response: dict) -> str:
    status = response.get("status")
    location = response.get("location")
    if status in {301, 302} and location:
        return f"{path} returned HTTP {status}; redirected; location={location}"
    label = {
        200: "exposed",
        401: "protected but exists",
        403: "protected but exists",
        404: "not found",
        500: "server error risk",
    }.get(status, "observed")
    return f"{path} returned HTTP {status}; {label}"


def _sensitive_path_interpretation(statuses: set[int | None]) -> str:
    parts = []
    if 200 in statuses:
        parts.append("HTTP 200 indicates a sensitive path may be directly exposed.")
    if 401 in statuses or 403 in statuses:
        parts.append("HTTP 401/403 indicates the path may exist but is protected; this is evidence for review, not a confirmed exposure.")
    if 301 in statuses or 302 in statuses:
        parts.append("HTTP 301/302 indicates redirection; review the Location target and whether redirects are intended.")
    if 404 in statuses:
        parts.append("HTTP 404 indicates the tested path was not found.")
    if 500 in statuses:
        parts.append("HTTP 500 indicates the probe triggered a server error and should be reviewed as a stability or information-disclosure risk.")
    return " ".join(parts) if parts else "No sensitive path signal was observed."

from __future__ import annotations

import hashlib
import re
import socket
import time
from uuid import uuid4
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from websecscope.guide import recommendation_for
from websecscope.models import FAIL, PASS, WARNING, Finding, RISK_HIGH, RISK_INFO, RISK_LOW, RISK_MEDIUM
from websecscope.rules.web import SECURITY_HEADERS, SENSITIVE_PATHS
from websecscope.rules.web.header_values import validate_header
from websecscope.rules.web.cookie_values import cookie_attributes
from websecscope.policy import evaluate_cookie, resource_decision, cookie_summary
from websecscope.response_body import read_body
from websecscope.rules.resource_formats import json_credential_configuration, html_diagnostic_credentials

HTTP_TIMEOUT_SECONDS = 1
socket.setdefaulttimeout(HTTP_TIMEOUT_SECONDS)


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


def scan_web_target(target: str, policy=None) -> list[Finding]:
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
    initial_method = "HEAD"
    if response["error"]:
        response = _request(target, method="GET")
        initial_method = "GET"
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

    # Identical method, headers, URL and redirect policy to the existing path control.
    # Reuse this observation only within this scan; do not reuse redirected GETs.
    root_get = _request(target, method="GET", follow_redirects=False)
    document_get = root_get
    if not root_get.get("error") and root_get.get("status") is not None and 300 <= root_get["status"] < 400:
        document_get = _request(target, method="GET")
    headers = {key.lower(): value for key, value in response["headers"].items()}
    get_headers = {key.lower(): value for key, value in document_get["headers"].items()}
    comparison_error = document_get.get("error")
    findings.extend(_scan_security_headers(headers, get_headers, urlparse(document_get.get("url", target)).scheme,
                                           comparison_error, initial_method,
                                           _policy_fields(response["headers"]), _policy_fields(document_get["headers"]),
                                           policy=policy, initial_url=response.get('url',target),
                                           get_url=document_get.get('url',target)))
    cookies = response["headers"].get_all("Set-Cookie", []) if hasattr(response["headers"], "get_all") else []
    get_cookies = document_get["headers"].get_all("Set-Cookie", []) if hasattr(document_get["headers"], "get_all") else []
    if policy is None:
        cookie_finding = _scan_cookie_flags(list(dict.fromkeys(cookies + get_cookies)))[0]
    else:
        cookie_finding = _scan_cookie_flags(cookies + get_cookies, policy=policy,
            urls=[response.get('url',target)]*len(cookies)+[document_get.get('url',target)]*len(get_cookies))[0]
    cookie_finding.metadata.update({"head_get_differ": cookies != get_cookies, "initial_method": initial_method,
                                   "initial_cookie_count": len(cookies), "get_cookie_count": len(get_cookies),
                                   "get_error": comparison_error, "validation_scope": "observed attributes; browser enforcement not verified"})
    if comparison_error and cookie_finding.status == PASS:
        cookie_finding.status, cookie_finding.risk = WARNING, RISK_LOW
        cookie_finding.evidence += f" GET observation incomplete: {comparison_error}"
        cookie_finding.recommendation = "Repeat the GET observation before concluding that cookie configuration is complete."
    findings.append(cookie_finding)
    findings.extend(_scan_sensitive_paths(target, root_response=root_get, policy=policy))
    return findings


def _request(url: str, method: str = "HEAD", follow_redirects: bool = True) -> dict:
    deadline=time.monotonic()+HTTP_TIMEOUT_SECONDS
    request = Request(url, method=method, headers={"User-Agent": "WebSecScope/1.0"})
    try:
        opener = build_opener() if follow_redirects else build_opener(_NoRedirectHandler)
        with opener.open(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            final_url=getattr(response,'geturl',lambda:url)()
            return {
                "status": response.status,
                "url": final_url,
                "requested_url": url, "redirected": final_url != url,
                "initial_status": None if final_url != url else response.status,
                "headers": response.headers,
                "location": response.headers.get("Location"),
                **read_body(response,method,deadline=deadline),
            }
    except HTTPError as exc:
        with exc:
            return {"status": exc.code, "headers": exc.headers, "location": exc.headers.get("Location"),
                    "url": exc.geturl(), "requested_url": url, "redirected": exc.geturl()!=url,
                    "initial_status": None if exc.geturl()!=url else exc.code, **read_body(exc,method,deadline=deadline)}
    except (HTTPException, TimeoutError, URLError, OSError) as exc:
        return {"status": None, "headers": {}, "error": f"{type(exc).__name__}: request failed"}


def _policy_fields(headers):
    """Preserve ordered repeated fields before the convenience mapping collapses them."""
    from websecscope.rules.web.header_policy import TARGET_HEADERS
    names = TARGET_HEADERS | {'content-security-policy-report-only'}
    if hasattr(headers, 'get_all'):
        return {name: headers.get_all(name, []) for name in names}
    return {name: [value for key, value in headers.items() if key.lower() == name] for name in names}


def _scan_security_headers(headers: dict[str, str], get_headers: dict[str, str] | None = None,
                           scheme: str | None = None, comparison_error: str | None = None,
                           initial_method: str = "HEAD", header_fields=None, get_header_fields=None,
                           policy=None, initial_url=None, get_url=None) -> list[Finding]:
    findings: list[Finding] = []
    for header_key, (header_name, risk) in SECURITY_HEADERS.items():
        from websecscope.rules.web.header_policy import TARGET_HEADERS, assess_header
        analysis = get_analysis = None
        if header_key in TARGET_HEADERS:
            fields = header_fields if header_fields is not None else _policy_fields(headers)
            get_fields = get_header_fields if get_header_fields is not None else _policy_fields(get_headers or {})
            values = fields.get(header_key, [])
            get_values = get_fields.get(header_key, [])
            analysis = assess_header(header_key, values, fields.get('content-security-policy-report-only', []))
            status, reason = analysis['status'], analysis['reason']
            if get_headers is not None and not comparison_error:
                get_analysis = assess_header(header_key, get_values, get_fields.get('content-security-policy-report-only', []))
            get_status, get_reason = (get_analysis['status'], get_analysis['reason']) if get_analysis else (None, None)
            mismatch = get_headers is not None and values != get_values
        else:
            status, reason = validate_header(header_key, headers.get(header_key, ""))
            get_status, get_reason = (validate_header(header_key, get_headers.get(header_key, ""))
                                      if get_headers is not None and not comparison_error else (None, None))
            mismatch = get_headers is not None and headers.get(header_key) != get_headers.get(header_key)
        statuses = {status, get_status}
        result = FAIL if FAIL in statuses else WARNING if WARNING in statuses or comparison_error or mismatch else PASS
        baseline_result = result
        decisions = []
        if analysis is not None and policy is not None:
            from websecscope.rules.web.header_requirements import evaluate_requirement
            for phase, method, url, observed, parsed_analysis, before, error in (
                    ('initial', initial_method, initial_url, values, analysis, status, None),
                    ('document', 'GET', get_url, get_values, get_analysis, get_status, comparison_error)):
                if url is None or (phase == 'document' and get_headers is None):
                    continue
                decision = evaluate_requirement(header_key, observed, parsed_analysis or {}, before,
                                                policy, url, error)
                if decision is not None:
                    decisions.append(dict(phase=phase, method=method, **decision))
            adjusted = [next((d['status'] for d in decisions if d['phase'] == 'initial'), status),
                        next((d['status'] for d in decisions if d['phase'] == 'document'), get_status)]
            result = FAIL if FAIL in adjusted else WARNING if WARNING in adjusted or comparison_error or mismatch else PASS
        findings.append(
            Finding(
                check_id=f"WEB_HEADER_{header_name.upper().replace('-', '_')}",
                category="web",
                title=f"{header_name} header",
                status=result,
                risk=RISK_INFO if result == PASS else risk,
                evidence=f"{initial_method} {header_name}: {headers.get(header_key)}; {reason}"
                    + (f"; GET: {get_headers.get(header_key)}; {get_reason}" if get_headers is not None else "")
                    + (f"; GET error: {comparison_error}" if comparison_error else ""),
                recommendation="No action required." if result == PASS else recommendation_for("WEB_HEADER_MISSING"),
                metadata={"validation_scope": "configuration syntax/values; attack exploitability is not established",
                          "initial_method": initial_method, "head_get_differ": mismatch,
                          "initial_status": status, "get_status": get_status, "get_error": comparison_error,
                          "scheme": scheme, "hsts_https_context": scheme == "https" if header_key == "strict-transport-security" else None,
                          "browser_enforcement_verified": False,
                          **({"policy_analysis": analysis, "get_policy_analysis": get_analysis,
                              "header_values": values, "get_header_values": get_values,
                              "validation_scope": "bounded policy semantics; service requirements/browser execution unverified"} if analysis is not None else {})},
            )
        )
        if decisions:
            finding = findings[-1]
            finding.title += ' (service requirement assessed)'
            finding.evidence += '; Service requirement assessment (not demonstrated exploitation): ' + '; '.join(
                d['method'] + ': ' + d['reason'] for d in decisions)
            finding.recommendation = ('No action required for the assessed requirement.' if result == PASS else
                                      'Review the declared header requirement and recorded policy evidence; this is not proof of exploitation.')
            finding.metadata.update(header_requirement_decisions=decisions, baseline_status=baseline_result,
                                    final_status=result, finding_kind='service_requirement_assessment',
                                    interpretation='Header service requirement compliance; actual exploitation is not established.')
    return findings


def _scan_cookie_flags(cookies: list[str], policy=None, urls=None) -> list[Finding]:
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

    details = [evaluate_cookie(cookie, urls[index] if urls else '', policy) for index,cookie in enumerate(cookies)]
    status = FAIL if any(d["status"] == FAIL for d in details) else WARNING if any(d["status"] == WARNING for d in details) else PASS

    return [
        Finding(
            check_id="WEB_COOKIE_FLAGS",
            category="web",
            title="Cookie security attributes",
            status=status,
            risk=RISK_MEDIUM if status != PASS else RISK_INFO,
            evidence="; ".join(f"{d['name']}: {cookie_summary(d, 'valid Secure, HttpOnly and SameSite attributes')}" for d in details),
            recommendation=recommendation_for("WEB_COOKIE_FLAGS") if status != PASS else "No action required.",
            metadata={"cookies": details, "browser_enforcement_verified": False},
        )
    ]


def _scan_sensitive_paths(target: str, root_response: dict | None = None, policy=None) -> list[Finding]:
    observations = []
    risk_statuses = set()
    base = target.rstrip("/") + "/"
    # A missing-path comparison can matter only after the root comparison matches.
    # Keep both controls for a catch-all decision, but fetch the second lazily.
    # This state belongs to this invocation only; no candidate response is cached.
    controls = [root_response if root_response is not None else _request(target, method="GET", follow_redirects=False)]
    details = []
    paths = list(SENSITIVE_PATHS)
    if policy is not None and policy.matches_origin(target):
        observed_paths = {urlparse(urljoin(base, path)).path for path in paths}
        paths += [path for path in policy.resources if path not in observed_paths]
    for path in paths:
        probe_url = urljoin(base, path)
        head = _request(probe_url, method="HEAD", follow_redirects=False)
        get = _request(probe_url, method="GET", follow_redirects=False)
        if (len(controls) == 1 and not controls[0].get("error")
                and controls[0].get("status") == 200 and not get.get("error")
                and get.get("status") is not None and 200 <= get["status"] < 300
                and get.get("body_sample", "").strip()
                and get["body_sample"].strip() == controls[0].get("body_sample", "").strip()):
            controls.append(_request(urljoin(base, f".websecscope-not-found-{uuid4().hex}"),
                                     method="GET", follow_redirects=False))
        outcome, reason = _classify_sensitive_response(path.lstrip('/'), get, controls)
        decision = resource_decision({'url':probe_url,'final_url':get.get('url',probe_url),
            'status_code':get.get('status'),'headers':dict(get.get('headers',{}).items()),
            'body_sample':get.get('body_sample',''),'body_truncated':get.get('body_truncated',False),
            'body_evidence':get.get('body_evidence',{}),'redirected':get.get('redirected',False),
            'error':get.get('error'),'unauthenticated_request':True,
            'response_kind':'public_shell' if outcome=='spa' else outcome}, policy)
        if decision is not None:
            if decision['status'] == FAIL:outcome='exposed'
            elif decision['status'] == PASS:
                if outcome=='exposed':
                    outcome='unconfirmed'
                    decision.update(status=WARNING,policy_conflict=True,reason='Public policy cannot waive a resource-specific exposure signature')
                else:outcome='policy_observed'
            else:outcome='unconfirmed'
            reason=decision['reason']
        # A successful GET can confirm exposure even if HEAD failed; otherwise
        # retain incomplete HEAD observations as a review signal.
        if head.get("error") and outcome == "absent":
            outcome, reason = "request_error", "HEAD failed; GET returned no resource"
        for method, response in (("HEAD", head), ("GET", get)):
            status = response.get("status")
            if status is not None:
                risk_statuses.add(status)
            observations.append(f"{method} {_sensitive_path_observation(path, response)}")
        observations.append(f"{path}: {outcome}; {reason}")
        details.append({"path": path, "outcome": outcome, "reason": reason,
                        "head": _path_response_metadata(head), "get": _path_response_metadata(get),
                        "head_get_differ": head.get("status") != get.get("status") or head.get("error") != get.get("error")})
        if decision is not None:details[-1]['policy_decision']=decision

    exposed = any(item["outcome"] == "exposed" for item in details)
    review = any(item["outcome"] not in {"absent", "spa", "exposed", "policy_observed"} for item in details)
    control_errors = any(response.get("error") for response in controls)
    review = review or control_errors

    return [
        Finding(
            check_id="WEB_SENSITIVE_PATHS",
            category="web",
            title="Sensitive path exposure",
            status=FAIL if exposed else WARNING if review else PASS,
            risk=RISK_HIGH if exposed else RISK_LOW if review else RISK_INFO,
            evidence="; ".join(observations) if observations else "No common sensitive paths responded as exposed.",
            recommendation=recommendation_for("WEB_SENSITIVE_PATH") if exposed or review else "No action required.",
            metadata={
                "description": "Sensitive path probes compare HEAD/GET and bounded GET content against root and missing-path controls.",
                "interpretation": "Exposure requires a resource-specific content signature; HTTP status alone does not confirm disclosure. "
                    "Protected, redirected, ambiguous, server-error and incomplete observations require review.",
                "http_statuses": sorted(status for status in risk_statuses if status is not None),
                "paths": details,
                "controls": [_path_response_metadata(response) for response in controls],
                "missing_control_requested": len(controls) == 2,
                "control_policy": "Missing-path GET is requested once per scan only when a successful candidate body matches the root body.",
                "complete": not control_errors and not any(
                    item[method]["error"] for item in details for method in ("head", "get")),
            },
        )
    ]


def _path_response_metadata(response: dict) -> dict:
    body = response.get("body_sample", "")
    return {"status": response.get("status"), "location": response.get("location"),
            "url":response.get('url'),"requested_url":response.get('requested_url'),"redirected":response.get('redirected',False),
            "initial_status":response.get('initial_status'),"body_truncated":response.get('body_truncated',False),
            "body_evidence":response.get('body_evidence',{}),
            "error": response.get("error"), "sample_length": len(body),
            "sample_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest() if body else None}


def _classify_sensitive_response(path: str, response: dict, controls: list[dict]) -> tuple[str, str]:
    if response.get("error"):
        return "request_error", "GET failed or response body could not be read"
    status = response.get("status")
    if status in {401, 403}:
        return "protected", "authentication or authorization required; protected but exists"
    if status is not None and 300 <= status < 400:
        return "redirected", "redirect observed without following Location"
    if status in {404, 410}:
        return "absent", "GET did not return a resource"
    if status is not None and status >= 500:
        return "server_error", "server error is not confirmed sensitive information exposure"
    if status is None or not 200 <= status < 300:
        return "unconfirmed", "unclassified GET status requires review"
    body = response.get("body_sample", "")
    if response.get('redirected'):
        return 'redirected','Final response cannot establish the original resource content'
    # A ZIP magic prefix is positive binary evidence, not a claim of complete text.
    if path == 'backup.zip' and not response.get('body_evidence',{}).get('unsupported_content_encoding') and body.startswith(('PK\x03\x04','PK\x05\x06','PK\x07\x08')):
        return 'exposed','GET contains a ZIP file signature'
    if response.get('body_evidence',{}).get('supported_for_text_analysis') is False:
        return 'unconfirmed','Body format/encoding/parse evidence prevents text analysis; review recorded body_evidence'
    html = bool(re.search(r"<(?:!doctype\s+html|html|head|body)\b", body, re.I))
    matches_controls = len(controls) == 2 and bool(body.strip()) and not response.get('body_truncated') and all(
        not control.get("error") and control.get("status") == 200
        and not control.get('body_truncated') and control.get('body_evidence',{}).get('supported_for_text_analysis',True)
        and body.strip() == control.get("body_sample", "").strip() for control in controls
    )
    if html and matches_controls:
        return "spa", "GET matches root and missing-path HTML controls (public catch-all shell)"
    if matches_controls:
        return "unconfirmed", "GET matches public root and missing-path content; resource identity is uncertain"
    if path == '.env' and not response.get('body_truncated') and json_credential_configuration(body):
        return 'exposed','GET contains complete structured identity/credential configuration under the environment resource'
    if path == 'phpinfo.php' and html_diagnostic_credentials(body):
        return 'exposed','GET contains a PHP diagnostics title and complete credential key/value table row'
    # These are general resource formats, not fixture values or status heuristics.
    if path == ".env" and not html and re.search(r"(?m)^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*\S+", body):
        return "exposed", "GET contains environment assignment syntax"
    if path == ".git/HEAD" and re.fullmatch(r"\s*(?:ref:\s+refs/[^\s]+|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\s*", body):
        return "exposed", "GET contains a Git HEAD reference or object ID"
    if path == "backup.zip" and body.startswith(("PK\x03\x04", "PK\x05\x06", "PK\x07\x08")):
        return "exposed", "GET contains a ZIP file signature"
    if path == "phpinfo.php" and re.search(r"phpinfo\s*\(", body, re.I) and re.search(r"PHP Version|PHP Variables|PHP License", body, re.I):
        return "exposed", "GET contains PHP diagnostic page markers"
    return "unconfirmed", "successful GET lacks a specific sensitive-resource signature"


def _sensitive_path_observation(path: str, response: dict) -> str:
    status = response.get("status")
    location = response.get("location")
    if response.get("error"):
        return f"{path} returned HTTP {status}; request error={response['error']}"
    if status in {301, 302} and location:
        return f"{path} returned HTTP {status}; redirected; location={location}"
    label = {
        200: "success; exposure requires GET content evidence",
        401: "protected but exists",
        403: "protected but exists",
        404: "not found",
        500: "server error risk",
    }.get(status, "observed")
    return f"{path} returned HTTP {status}; {label}"


def _sensitive_path_interpretation(statuses: set[int | None]) -> str:
    parts = []
    if 200 in statuses:
        parts.append("HTTP 200 alone does not confirm exposure; GET content evidence is required.")
    if 401 in statuses or 403 in statuses:
        parts.append("HTTP 401/403 indicates the path may exist but is protected; this is evidence for review, not a confirmed exposure.")
    if 301 in statuses or 302 in statuses:
        parts.append("HTTP 301/302 indicates redirection; review the Location target and whether redirects are intended.")
    if 404 in statuses:
        parts.append("HTTP 404 indicates the tested path was not found.")
    if 500 in statuses:
        parts.append("HTTP 500 indicates the probe triggered a server error and should be reviewed as a stability or information-disclosure risk.")
    return " ".join(parts) if parts else "No sensitive path signal was observed."

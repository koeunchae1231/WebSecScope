from __future__ import annotations

import socket
import queue
import threading
import time
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen
from uuid import uuid4
from typing import Any, Mapping

from websecscope.rules.api_evidence import html_response, response_kind
from websecscope.response_body import inspect_body, read_body

API_PATHS = [
    "/api",
    "/api/users",
    "/api/login",
    "/api/auth",
    "/api/admin",
    "/admin",
    "/swagger",
    "/api-docs",
    "/openapi.json",
]

REFLECTION_TEST_ORIGIN = "https://websecscope.local"
SECOND_REFLECTION_ORIGIN = "https://websecscope-probe.invalid"
HTTP_TIMEOUT_SECONDS = 1
socket.setdefaulttimeout(HTTP_TIMEOUT_SECONDS)


def scan_api_endpoints(target: str) -> dict:
    if not _valid_target(target):
        return {"enabled": True, "error": "Target URL must include http:// or https://.", "endpoints": []}

    endpoints = []
    for path in API_PATHS:
        url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
        observation = request_observation(url)
        if observation["status_code"] is not None and observation.get("cors", {}).get("access_control_allow_origin"):
            reflection = request_observation(url, headers={"Origin": REFLECTION_TEST_ORIGIN})
            if reflection.get("cors", {}).get("access_control_allow_origin") == REFLECTION_TEST_ORIGIN:
                observation["cors"]["origin_reflection_observed"] = True
                second = request_observation(url, headers={"Origin": SECOND_REFLECTION_ORIGIN})
                observation["cors"]["probes"] = [{"origin": REFLECTION_TEST_ORIGIN, "response": reflection},
                                                {"origin": SECOND_REFLECTION_ORIGIN, "response": second}]
            else:
                observation["cors"]["probes"] = [{"origin": REFLECTION_TEST_ORIGIN, "response": reflection}]
        endpoints.append(
            {
                "path": path,
                "url": url,
                **endpoint_observation(observation),
                "redirected": observation.get("redirected", False),
                "final_url": observation.get("final_url"),
                "unauthenticated_request": True,
            }
        )
    controls = []
    if any('admin' in e['path'].lower() and e['status_code'] in {200,201,202,204}
           and not e.get('redirected') and html_response(e) for e in endpoints):
        controls = [request_observation(target), request_observation(urljoin(target.rstrip('/')+'/', f'.websecscope-api-missing-{uuid4().hex}'))]
    for endpoint in endpoints:
        endpoint['response_kind'] = response_kind(endpoint, controls)
    return {"enabled": True, "candidate_paths": API_PATHS, "endpoints": endpoints, "controls": controls}


def endpoint_observation(observation: Mapping[str, Any]) -> dict[str, Any]:
    """Project shared evidence into an endpoint without collecting or judging it.

    Required keys retain their original KeyError contract; optional evidence keeps
    its defaults. Nested evidence is passed through, as in the original scanners.
    """
    return {
        "status_code": observation["status_code"],
        "content_type": observation["content_type"],
        "server": observation["server"],
        "cors": observation["cors"],
        "www_authenticate": observation["www_authenticate"],
        "set_cookie": observation["set_cookie"],
        "headers": observation["headers"],
        "body_sample": observation["body_sample"],
        "body_truncated": observation.get("body_truncated", False),
        "body_evidence": observation.get("body_evidence", {}),
        "headers_list": observation.get("headers_list", []),
        "redirect_observation": observation.get("redirect_observation", {}),
        "error": observation["error"],
    }


def request_observation(url: str, headers: dict[str, str] | None = None) -> dict:
    results: queue.Queue[dict] = queue.Queue(maxsize=1)
    worker = threading.Thread(target=_request_observation_direct, args=(url, headers, results), daemon=True)
    worker.start()
    try:
        return results.get(timeout=HTTP_TIMEOUT_SECONDS + 0.5)
    except queue.Empty:
        return _build_observation(None, {}, b"", "TimeoutError: request deadline exceeded")


def _request_observation_direct(url: str, headers: dict[str, str] | None, results: queue.Queue[dict]) -> None:
    deadline=time.monotonic()+HTTP_TIMEOUT_SECONDS
    request_headers = {"User-Agent": "WebSecScope/1.0"}
    if headers:
        request_headers.update(headers)
    request = Request(url, method="GET", headers=request_headers)
    try:
        with urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            observation = _build_observation(response.status, response.headers, b'', None,
                                             body_observation=read_body(response,deadline=deadline))
            _response_urls(observation,url,response.geturl())
            results.put(observation)
    except HTTPError as exc:
        with exc:
            observation = _build_observation(exc.code, exc.headers, b'', None,
                                             body_observation=read_body(exc,deadline=deadline))
            _response_urls(observation,url,exc.geturl())
            results.put(observation)
    except (HTTPException, TimeoutError, URLError, OSError) as exc:
        results.put(_build_observation(None, {}, b"", f"{type(exc).__name__}: request failed"))


def _build_observation(status_code: int | None, headers, raw_body: bytes, error: str | None, *, body_observation=None) -> dict:
    body = body_observation if body_observation is not None else inspect_body(raw_body,headers,read_error=error)
    return {
        "status_code": status_code,
        "content_type": _header(headers, "Content-Type"),
        "server": _header(headers, "Server"),
        "www_authenticate": _header(headers, "WWW-Authenticate"),
        "set_cookie": headers.get_all("Set-Cookie", []) if hasattr(headers, "get_all") else [],
        "cors": {
            "access_control_allow_origin": _header(headers, "Access-Control-Allow-Origin"),
            "access_control_allow_credentials": _header(headers, "Access-Control-Allow-Credentials"),
            "access_control_allow_methods": _header(headers, "Access-Control-Allow-Methods"),
            "access_control_allow_headers": _header(headers, "Access-Control-Allow-Headers"),
            "origin_reflection_observed": False,
        },
        "headers": dict(headers.items()) if hasattr(headers, "items") else {},
        **body,
        "headers_list": list(headers.items()) if hasattr(headers,'items') else [],
        "error": body['error'],
        "redirected": False,
        "final_url": None,
    }


def _header(headers, name: str) -> str | None:
    if hasattr(headers, "items"):
        return next((v for k,v in headers.items() if k.lower()==name.lower()),None)
    return None


def _response_urls(observation,requested,final):
    redirected=final!=requested
    observation.update(final_url=final,redirected=redirected,redirect_observation={
        'requested_url':requested,'final_url':final,'initial_status':None if redirected else observation['status_code'],
        'final_status':observation['status_code'],'history_collected':not redirected})


def _valid_target(target: str) -> bool:
    parsed = urlparse(target)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)

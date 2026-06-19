from __future__ import annotations

import socket
import queue
import threading
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

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
        endpoints.append(
            {
                "path": path,
                "url": url,
                "status_code": observation["status_code"],
                "content_type": observation["content_type"],
                "server": observation["server"],
                "cors": observation["cors"],
                "www_authenticate": observation["www_authenticate"],
                "set_cookie": observation["set_cookie"],
                "headers": observation["headers"],
                "body_sample": observation["body_sample"],
                "error": observation["error"],
            }
        )
    return {"enabled": True, "candidate_paths": API_PATHS, "endpoints": endpoints}


def request_observation(url: str, headers: dict[str, str] | None = None) -> dict:
    results: queue.Queue[dict] = queue.Queue(maxsize=1)
    worker = threading.Thread(target=_request_observation_direct, args=(url, headers, results), daemon=True)
    worker.start()
    try:
        return results.get(timeout=HTTP_TIMEOUT_SECONDS + 0.5)
    except queue.Empty:
        return _build_observation(None, {}, b"", "TimeoutError: request deadline exceeded")


def _request_observation_direct(url: str, headers: dict[str, str] | None, results: queue.Queue[dict]) -> None:
    request_headers = {"User-Agent": "WebSecScope/1.0"}
    if headers:
        request_headers.update(headers)
    request = Request(url, method="GET", headers=request_headers)
    try:
        with urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            raw_body = response.read(4096)
            results.put(_build_observation(response.status, response.headers, raw_body, None))
    except HTTPError as exc:
        raw_body = exc.read(4096)
        results.put(_build_observation(exc.code, exc.headers, raw_body, None))
    except (HTTPException, TimeoutError, URLError, OSError) as exc:
        results.put(_build_observation(None, {}, b"", f"{type(exc).__name__}: request failed"))


def _build_observation(status_code: int | None, headers, raw_body: bytes, error: str | None) -> dict:
    body_sample = raw_body.decode("utf-8", errors="replace")
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
        "body_sample": body_sample,
        "error": error,
    }


def _header(headers, name: str) -> str | None:
    if hasattr(headers, "get"):
        return headers.get(name)
    return None


def _valid_target(target: str) -> bool:
    parsed = urlparse(target)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)

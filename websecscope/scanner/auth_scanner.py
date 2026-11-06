from __future__ import annotations

from urllib.parse import urljoin

from websecscope.scanner.api_scanner import endpoint_observation, request_observation

AUTH_PATH_MARKERS = ("login", "auth", "signin")


def scan_auth_controls(target: str, api_scan: dict) -> dict:
    endpoints = api_scan.get("endpoints", [])
    auth_endpoints = [endpoint for endpoint in endpoints if _is_auth_path(endpoint.get("path", ""))]

    observed_paths = {endpoint.get("path") for endpoint in auth_endpoints}
    for path in ["/login", "/signin"]:
        if path in observed_paths:
            continue
        url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
        observation = request_observation(url)
        auth_endpoints.append(
            {
                "path": path,
                "url": url,
                **endpoint_observation(observation),
                "final_url": observation.get("final_url"),
                "redirected": observation.get("redirected", False),
            }
        )

    return {
        "enabled": True,
        "request_policy": "One unauthenticated GET per candidate path; no brute force or bypass attempts.",
        "auth_paths": auth_endpoints,
    }


def _is_auth_path(path: str) -> bool:
    lower_path = path.lower()
    return any(marker in lower_path for marker in AUTH_PATH_MARKERS)

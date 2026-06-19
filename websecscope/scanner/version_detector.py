from __future__ import annotations

import re
import socket
import ssl
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

VERSION_PATTERNS = [
    re.compile(r"(?P<product>OpenSSH)[_-](?P<version>\d+(?:\.\d+)+[A-Za-z0-9._-]*)", re.IGNORECASE),
    re.compile(r"(?P<product>nginx)/(?P<version>\d+(?:\.\d+)+[A-Za-z0-9._-]*)", re.IGNORECASE),
    re.compile(r"(?P<product>Apache)/(?P<version>\d+(?:\.\d+)+[A-Za-z0-9._-]*)", re.IGNORECASE),
    re.compile(r"(?P<product>[A-Za-z][A-Za-z0-9_.+-]*)/(?P<version>\d+(?:\.\d+)+[A-Za-z0-9._-]*)"),
]

HTTP_VERSION_HEADERS = ("Server", "X-Powered-By", "Via")
TIMEOUT_SECONDS = 1.0


def detect_versions(service_detection: dict, host: str = "127.0.0.1") -> dict:
    items = []
    for service in service_detection.get("items", []):
        enriched = service.copy()
        observation = _observe_service(host, service)
        enriched.update(observation)
        normalized = normalize_version(observation.get("banner", ""))
        enriched["detected_product"] = normalized["product"]
        enriched["version"] = normalized["version"]
        enriched["normalized_service"] = normalized
        items.append(enriched)
    return {
        "enabled": True,
        "host": host,
        "policy": "Safe banner/header observation only; no authentication, command execution, or aggressive probing.",
        "items": items,
    }


def normalize_version(value: str) -> dict:
    for pattern in VERSION_PATTERNS:
        match = pattern.search(value or "")
        if match:
            product = match.group("product")
            version = match.group("version")
            return {"product": product, "version": version}
    return {"product": "unknown", "version": "unknown"}


def _observe_service(host: str, service: dict) -> dict:
    name = service.get("service", "unknown")
    port = int(service.get("port", 0))
    if name == "SSH":
        return _read_ssh_banner(host, port)
    if name in {"HTTP", "HTTP-alt"}:
        return _read_http_headers(f"http://{host}:{port}/")
    if name in {"HTTPS", "HTTPS-alt"}:
        return _read_http_headers(f"https://{host}:{port}/")
    return {
        "banner": "",
        "evidence": f"{service.get('evidence')}; version not observed without active protocol probing.",
        "confidence": service.get("confidence", "low"),
    }


def _read_ssh_banner(host: str, port: int) -> dict:
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT_SECONDS) as connection:
            connection.settimeout(TIMEOUT_SECONDS)
            banner = connection.recv(200).decode("utf-8", errors="replace").strip()
    except OSError:
        banner = ""
    if not banner:
        return {"banner": "", "evidence": "SSH banner version not observed.", "confidence": "medium"}
    return {"banner": banner, "evidence": f"SSH server banner observed: {banner}", "confidence": "high"}


def _read_http_headers(url: str) -> dict:
    request = Request(url, method="HEAD", headers={"User-Agent": "WebSecScope/1.0"})
    try:
        with urlopen(request, timeout=TIMEOUT_SECONDS, context=_ssl_context(url)) as response:
            headers = response.headers
    except HTTPError as exc:
        headers = exc.headers
    except (OSError, URLError, TimeoutError, TypeError):
        return {"banner": "", "evidence": "HTTP version headers not observed.", "confidence": "medium"}

    parts = [f"{header}: {headers.get(header)}" for header in HTTP_VERSION_HEADERS if headers.get(header)]
    banner = "; ".join(parts)
    if not banner:
        return {"banner": "", "evidence": "HTTP version headers not observed.", "confidence": "medium"}
    return {"banner": banner, "evidence": f"HTTP version header(s) observed: {banner}", "confidence": "high"}


def _ssl_context(url: str):
    if not url.startswith("https://"):
        return None
    return ssl.create_default_context()

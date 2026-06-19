from __future__ import annotations

from websecscope.scanner.linux import get_listening_ports

PORT_SERVICE_MAP = {
    21: ("FTP", "well-known TCP port 21"),
    22: ("SSH", "well-known TCP port 22"),
    23: ("Telnet", "well-known TCP port 23"),
    25: ("SMTP", "well-known TCP port 25"),
    53: ("DNS", "well-known TCP port 53"),
    80: ("HTTP", "well-known TCP port 80"),
    110: ("POP3", "well-known TCP port 110"),
    143: ("IMAP", "well-known TCP port 143"),
    443: ("HTTPS", "well-known TCP port 443"),
    3306: ("MySQL/MariaDB", "well-known TCP port 3306"),
    5432: ("PostgreSQL", "well-known TCP port 5432"),
    6379: ("Redis", "well-known TCP port 6379"),
    8080: ("HTTP-alt", "common alternate HTTP port 8080"),
    8443: ("HTTPS-alt", "common alternate HTTPS port 8443"),
    27017: ("MongoDB", "well-known TCP port 27017"),
}


def detect_services() -> dict:
    ports = get_listening_ports()
    services = [_service_item(port) for port in ports]
    return {
        "enabled": True,
        "source": "/proc/net/tcp and /proc/net/tcp6",
        "items": services,
        "evidence": "No listening TCP ports found or Linux /proc data unavailable." if not services else f"{len(services)} listening TCP port(s) mapped.",
    }


def _service_item(port: int) -> dict:
    service, basis = PORT_SERVICE_MAP.get(port, ("unknown", "port is not in the built-in common service map"))
    confidence = "medium" if service != "unknown" else "low"
    return {
        "port": port,
        "protocol": "tcp",
        "service": service,
        "version": "unknown",
        "banner": "",
        "evidence": basis,
        "confidence": confidence,
        "detected_product": "unknown",
        "normalized_service": {
            "product": "unknown",
            "version": "unknown",
        },
    }

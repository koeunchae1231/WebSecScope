from __future__ import annotations

from pathlib import Path

TCP_STATES = {"0A": "LISTEN"}


def get_listening_ports() -> list[int]:
    proc_path = Path("/proc/net/tcp")
    if not proc_path.exists():
        return []
    return sorted(_read_listening_ports(Path("/proc/net/tcp")) | _read_listening_ports(Path("/proc/net/tcp6")))


def _read_listening_ports(path: Path) -> set[int]:
    ports: set[int] = set()
    if not path.exists():
        return ports
    try:
        lines = path.read_text(encoding="utf-8").splitlines()[1:]
    except OSError:
        return ports
    for line in lines:
        parts = line.split()
        if len(parts) < 4 or TCP_STATES.get(parts[3]) != "LISTEN":
            continue
        local_address = parts[1]
        _, port_hex = local_address.rsplit(":", 1)
        ports.add(int(port_hex, 16))
    return ports

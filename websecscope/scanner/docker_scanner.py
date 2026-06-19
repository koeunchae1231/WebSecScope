from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any

SECRET_KEY_MARKERS = ("SECRET", "TOKEN", "PASSWORD", "PASSWD", "KEY", "AWS", "DB_PASSWORD", "PRIVATE")


def scan_docker_security() -> dict[str, Any]:
    docker_path = shutil.which("docker")
    if not docker_path:
        return _skipped("Docker not available", {"docker_cli": False})

    version = _run_docker(["docker", "version", "--format", "{{json .}}"])
    if version["returncode"] != 0:
        return _skipped("Docker daemon not running or not reachable", {"docker_cli": True, "version_error": version["error"] or version["output"]})

    ps = _run_docker(["docker", "ps", "--no-trunc", "--format", "{{json .}}"])
    if ps["returncode"] != 0:
        return _skipped("Docker daemon not running or container list unavailable", {"docker_cli": True, "ps_error": ps["error"] or ps["output"]})

    summaries = _parse_ps_json_lines(ps["output"])
    container_ids = [item.get("ID") for item in summaries if item.get("ID")]
    containers = []
    for container_id in container_ids:
        inspected = _inspect_container(container_id)
        if inspected:
            containers.append(_normalize_container(inspected, summaries))

    return {
        "status": "completed",
        "environment": {
            "docker_cli": True,
            "docker_version": _parse_json_or_text(version["output"]),
        },
        "containers": containers,
        "images": _image_summary(containers),
        "evidence": [f"docker ps observed {len(containers)} running container(s)."],
    }


def _skipped(reason: str, environment: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "skipped",
        "reason": reason,
        "environment": environment,
        "containers": [],
        "images": [],
        "evidence": [reason],
    }


def _run_docker(command: list[str]) -> dict[str, Any]:
    try:
        result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=8)
    except PermissionError:
        return {"returncode": None, "output": "", "error": "permission denied"}
    except (OSError, subprocess.SubprocessError) as exc:
        return {"returncode": None, "output": "", "error": f"{type(exc).__name__}: docker command failed"}
    return {
        "returncode": result.returncode,
        "output": (result.stdout or "").strip(),
        "error": (result.stderr or "").strip(),
    }


def _parse_ps_json_lines(output: str) -> list[dict[str, Any]]:
    items = []
    for line in output.splitlines():
        try:
            items.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return items


def _inspect_container(container_id: str) -> dict[str, Any] | None:
    result = _run_docker(["docker", "inspect", container_id])
    if result["returncode"] != 0:
        return None
    try:
        payload = json.loads(result["output"])
    except json.JSONDecodeError:
        return None
    return payload[0] if payload else None


def _normalize_container(details: dict[str, Any], summaries: list[dict[str, Any]]) -> dict[str, Any]:
    config = details.get("Config", {}) or {}
    host_config = details.get("HostConfig", {}) or {}
    network_settings = details.get("NetworkSettings", {}) or {}
    state = details.get("State", {}) or {}
    image = config.get("Image") or details.get("Image") or "unknown"
    name = str(details.get("Name", "")).lstrip("/") or details.get("Id", "")[:12]
    env_keys = _env_keys(config.get("Env") or [])
    mounts = [_normalize_mount(mount) for mount in details.get("Mounts", []) or []]
    ports = _normalize_ports(network_settings.get("Ports") or {}, host_config.get("PortBindings") or {})
    return {
        "id": details.get("Id", "")[:12],
        "name": name,
        "image": image,
        "image_digest_pinned": "@" in image and "sha256:" in image,
        "image_tag": _image_tag(image),
        "status": state.get("Status") or _summary_value(summaries, details.get("Id"), "Status"),
        "ports": ports,
        "command": _summary_value(summaries, details.get("Id"), "Command") or config.get("Cmd"),
        "user": config.get("User") or "",
        "privileged": bool(host_config.get("Privileged")),
        "restart_policy": (host_config.get("RestartPolicy") or {}).get("Name", ""),
        "network_mode": host_config.get("NetworkMode", ""),
        "pid_mode": host_config.get("PidMode", ""),
        "ipc_mode": host_config.get("IpcMode", ""),
        "readonly_rootfs": bool(host_config.get("ReadonlyRootfs")),
        "cap_add": host_config.get("CapAdd") or [],
        "cap_drop": host_config.get("CapDrop") or [],
        "mounts": mounts,
        "env_keys": env_keys,
        "secret_like_env_keys": [key for key in env_keys if _secret_like(key)],
        "labels": sorted((config.get("Labels") or {}).keys()),
    }


def _normalize_mount(mount: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": mount.get("Type"),
        "source": mount.get("Source"),
        "destination": mount.get("Destination"),
        "mode": mount.get("Mode"),
        "rw": mount.get("RW"),
    }


def _normalize_ports(ports: dict[str, Any], bindings: dict[str, Any]) -> list[dict[str, Any]]:
    items = []
    source = ports or bindings
    for container_port, host_bindings in source.items():
        for binding in host_bindings or []:
            items.append(
                {
                    "container_port": container_port,
                    "host_ip": binding.get("HostIp", ""),
                    "host_port": binding.get("HostPort", ""),
                    "external": binding.get("HostIp", "") in {"", "0.0.0.0", "::"},
                }
            )
    return items


def _env_keys(env_values: list[str]) -> list[str]:
    keys = []
    for value in env_values:
        key = value.split("=", 1)[0]
        if key:
            keys.append(key)
    return sorted(set(keys))


def _secret_like(key: str) -> bool:
    upper = key.upper()
    return any(marker in upper for marker in SECRET_KEY_MARKERS)


def _image_tag(image: str) -> str:
    if "@" in image:
        image = image.split("@", 1)[0]
    last = image.rsplit("/", 1)[-1]
    if ":" not in last:
        return "missing"
    return last.rsplit(":", 1)[-1] or "missing"


def _image_summary(containers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = {}
    for container in containers:
        image = container.get("image", "unknown")
        seen[image] = {
            "image": image,
            "tag": container.get("image_tag", "unknown"),
            "digest_pinned": container.get("image_digest_pinned", False),
        }
    return list(seen.values())


def _summary_value(summaries: list[dict[str, Any]], full_id: str | None, key: str) -> Any:
    if not full_id:
        return None
    for summary in summaries:
        if full_id.startswith(str(summary.get("ID", ""))) or str(summary.get("ID", "")).startswith(full_id[:12]):
            return summary.get(key)
    return None


def _parse_json_or_text(value: str) -> Any:
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value

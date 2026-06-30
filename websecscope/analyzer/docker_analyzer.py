from __future__ import annotations

from typing import Any

from websecscope.guide import recommendation_for
from websecscope.models import FAIL, PASS, WARNING, Finding, RISK_CRITICAL, RISK_HIGH, RISK_INFO, RISK_LOW, RISK_MEDIUM, build_finding

RISKY_CAPABILITIES = {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH"}
SENSITIVE_HOST_PATHS = ("/", "/etc", "/var", "/home", "/root")
DB_IMAGE_MARKERS = ("mysql", "mariadb", "postgres", "redis", "mongo")


def analyze_docker_scan(docker_scan: dict[str, Any]) -> list[Finding]:
    if docker_scan.get("status") == "skipped":
        return [
            _finding(
                "DOCKER_SCAN_SKIPPED",
                "Docker checks skipped",
                PASS,
                RISK_INFO,
                "Docker checks were skipped because Docker is unavailable or the daemon is not reachable.",
                "; ".join(docker_scan.get("evidence", [])),
                "Run WebSecScope on an authorized Docker host to collect container security checks.",
            )
        ]
    containers = docker_scan.get("containers", [])
    if not containers:
        return [
            _finding(
                "DOCKER_RUNNING_CONTAINERS",
                "Running Docker containers",
                PASS,
                RISK_INFO,
                "Docker is available and no running containers were observed.",
                "; ".join(docker_scan.get("evidence", [])),
                "No action required.",
            )
        ]

    findings = []
    for container in containers:
        findings.extend(_analyze_container(container))
    findings.append(_summary_finding(containers))
    return findings


def _analyze_container(container: dict[str, Any]) -> list[Finding]:
    findings = []
    name = container.get("name", "unknown")
    image = container.get("image", "unknown")
    tag = container.get("image_tag", "unknown")
    if tag in {"latest", "missing"}:
        findings.append(_finding(f"DOCKER_IMAGE_TAG_{name}", "Docker image tag review", WARNING, RISK_LOW, "Images should be pinned to explicit immutable versions or digests.", f"container={name}; image={image}; tag={tag}; digest_pinned={container.get('image_digest_pinned')}", recommendation_for("DOCKER_IMAGE_TAG")))
    if not container.get("image_digest_pinned"):
        findings.append(_finding(f"DOCKER_DIGEST_PINNING_{name}", "Docker image digest not pinned", WARNING, RISK_LOW, "Digest pinning improves deployment reproducibility and supply-chain review.", f"container={name}; image={image}", recommendation_for("DOCKER_DIGEST_PINNING")))
    if container.get("privileged"):
        findings.append(_finding(f"DOCKER_PRIVILEGED_{name}", "Privileged container", FAIL, RISK_HIGH, "Privileged containers have broad host capabilities and should be avoided.", f"container={name}; privileged=true", recommendation_for("DOCKER_PRIVILEGED")))
    user = container.get("user") or "root"
    if user in {"", "0", "root"}:
        findings.append(_finding(f"DOCKER_ROOT_USER_{name}", "Container runs as root", WARNING, RISK_MEDIUM, "Running as root increases impact if the container is compromised.", f"container={name}; user={user}", recommendation_for("DOCKER_ROOT_USER")))
    if container.get("network_mode") == "host":
        findings.append(_finding(f"DOCKER_HOST_NETWORK_{name}", "Host network mode enabled", FAIL, RISK_HIGH, "Host networking removes Docker network isolation.", f"container={name}; network_mode=host", recommendation_for("DOCKER_HOST_NETWORK")))
    if container.get("pid_mode") == "host":
        findings.append(_finding(f"DOCKER_HOST_PID_{name}", "Host PID namespace enabled", FAIL, RISK_HIGH, "Host PID mode exposes host process namespace to the container.", f"container={name}; pid_mode=host", recommendation_for("DOCKER_HOST_NAMESPACE")))
    if container.get("ipc_mode") == "host":
        findings.append(_finding(f"DOCKER_HOST_IPC_{name}", "Host IPC namespace enabled", FAIL, RISK_HIGH, "Host IPC mode reduces process isolation.", f"container={name}; ipc_mode=host", recommendation_for("DOCKER_HOST_NAMESPACE")))
    if not container.get("readonly_rootfs"):
        findings.append(_finding(f"DOCKER_READONLY_ROOTFS_{name}", "Writable container root filesystem", WARNING, RISK_LOW, "Read-only root filesystems reduce persistence opportunities inside containers.", f"container={name}; readonly_rootfs=false", recommendation_for("DOCKER_READONLY_ROOTFS")))
    risky_caps = sorted(set(container.get("cap_add", [])) & RISKY_CAPABILITIES)
    if risky_caps:
        findings.append(_finding(f"DOCKER_RISKY_CAPS_{name}", "Risky Linux capabilities added", FAIL, RISK_HIGH, "Added high-risk capabilities can weaken container isolation.", f"container={name}; cap_add={risky_caps}", recommendation_for("DOCKER_RISKY_CAPS")))
    if not container.get("cap_drop"):
        findings.append(_finding(f"DOCKER_CAP_DROP_{name}", "No capabilities dropped", WARNING, RISK_LOW, "Dropping unused capabilities reduces container privileges.", f"container={name}; cap_drop=[]", recommendation_for("DOCKER_CAP_DROP")))
    findings.extend(_analyze_mounts(container))
    findings.extend(_analyze_env(container))
    findings.extend(_analyze_ports(container))
    return findings


def _analyze_mounts(container: dict[str, Any]) -> list[Finding]:
    findings = []
    name = container.get("name", "unknown")
    for mount in container.get("mounts", []):
        source = mount.get("source") or ""
        destination = mount.get("destination") or ""
        if destination == "/var/run/docker.sock" or source == "/var/run/docker.sock":
            findings.append(_finding(f"DOCKER_SOCKET_MOUNT_{name}", "Docker socket mounted into container", FAIL, RISK_CRITICAL, "Mounting docker.sock can grant control over the Docker host.", f"container={name}; source={source}; destination={destination}", recommendation_for("DOCKER_SOCKET_MOUNT")))
        elif source in SENSITIVE_HOST_PATHS or any(source.startswith(path + "/") for path in SENSITIVE_HOST_PATHS if path != "/"):
            findings.append(_finding(f"DOCKER_SENSITIVE_MOUNT_{name}", "Sensitive host path mounted", WARNING, RISK_MEDIUM, "Sensitive host path mounts should be tightly scoped and reviewed.", f"container={name}; source={source}; destination={destination}; rw={mount.get('rw')}", recommendation_for("DOCKER_SENSITIVE_MOUNT")))
    return findings


def _analyze_env(container: dict[str, Any]) -> list[Finding]:
    keys = container.get("secret_like_env_keys", [])
    if not keys:
        return []
    return [
        _finding(
            f"DOCKER_SECRET_ENV_{container.get('name', 'unknown')}",
            "Secret-like environment key observed",
            WARNING,
            RISK_HIGH,
            "Secret-like environment variable names were observed. Values are intentionally not collected or reported.",
            f"container={container.get('name')}; env_keys={keys}",
            recommendation_for("DOCKER_SECRET_ENV"),
        )
    ]


def _analyze_ports(container: dict[str, Any]) -> list[Finding]:
    findings = []
    external_ports = [port for port in container.get("ports", []) if port.get("external")]
    if external_ports:
        findings.append(_finding(f"DOCKER_EXTERNAL_PORTS_{container.get('name', 'unknown')}", "Container port bound on all interfaces", WARNING, RISK_LOW, "Ports bound to 0.0.0.0 or :: are reachable from outside the host network boundary when firewall rules permit.", f"container={container.get('name')}; ports={external_ports}", recommendation_for("DOCKER_EXTERNAL_PORTS")))
    image_lower = str(container.get("image", "")).lower()
    if external_ports and any(marker in image_lower for marker in DB_IMAGE_MARKERS):
        findings.append(_finding(f"DOCKER_DB_EXTERNAL_{container.get('name', 'unknown')}", "Database-like container exposed externally", WARNING, RISK_HIGH, "Database, Redis, or MongoDB containers should usually not be exposed on public interfaces.", f"container={container.get('name')}; image={container.get('image')}; ports={external_ports}", recommendation_for("DOCKER_DB_EXTERNAL")))
    return findings


def _summary_finding(containers: list[dict[str, Any]]) -> Finding:
    return _finding(
        "DOCKER_CONTAINER_INVENTORY",
        "Docker container inventory",
        PASS,
        RISK_INFO,
        "Docker running container metadata was collected using read-only docker ps and inspect commands.",
        f"containers={len(containers)}; names={[container.get('name') for container in containers]}",
        "No action required.",
    )


def _finding(
    check_id: str,
    title: str,
    status: str,
    risk: str,
    description: str,
    evidence: str,
    recommendation: str,
) -> Finding:
    return build_finding(check_id, "docker", title, status, risk, evidence, recommendation, description=description)

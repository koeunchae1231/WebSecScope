from __future__ import annotations

import getpass
import os
import platform
import shutil
import socket
import stat
import subprocess
from pathlib import Path
from typing import Any

from websecscope.scanner.linux import get_listening_ports

SSH_CONFIG_PATH = Path("/etc/ssh/sshd_config")
OS_RELEASE_PATH = Path("/etc/os-release")
PASSWD_PATH = Path("/etc/passwd")
SHADOW_PATH = Path("/etc/shadow")
SUDOERS_PATHS = [Path("/etc/sudoers"), Path("/etc/sudoers.d")]
TMP_PATHS = [Path("/tmp"), Path("/var/tmp")]
SUID_SCAN_DIRS = [Path("/usr/bin"), Path("/bin"), Path("/usr/sbin"), Path("/sbin")]
EXPECTED_SUID_NAMES = {
    "chfn",
    "chsh",
    "mount",
    "newgrp",
    "passwd",
    "su",
    "sudo",
    "umount",
    "gpasswd",
    "pkexec",
}


def scan_linux_security() -> dict[str, Any]:
    if platform.system().lower() != "linux":
        return {
            "status": "skipped",
            "environment": {"platform": platform.system(), "is_linux": False},
            "system_info": {},
            "ssh_config": {},
            "firewall": {},
            "file_permissions": {},
            "accounts": {},
            "evidence": ["Linux-specific checks are only available on Linux environments."],
        }

    scan = {
        "status": "completed",
        "environment": {"platform": platform.system(), "is_linux": True},
        "system_info": _collect_system_info(),
        "ssh_config": _collect_ssh_config(),
        "firewall": _collect_firewall_status(),
        "file_permissions": _collect_file_permissions(),
        "accounts": _collect_accounts(),
        "open_ports": get_listening_ports(),
        "evidence": [],
    }
    scan["evidence"].append("Linux checks completed using read-only files and commands.")
    return scan


def _collect_system_info() -> dict[str, Any]:
    os_release = _parse_key_value_file(OS_RELEASE_PATH)
    return {
        "os_name": os_release.get("NAME", "unknown"),
        "os_version": os_release.get("VERSION", os_release.get("VERSION_ID", "unknown")),
        "kernel_version": platform.release(),
        "hostname": socket.gethostname(),
        "current_user": getpass.getuser(),
        "is_root": hasattr(os, "geteuid") and os.geteuid() == 0,
        "package_manager": _detect_package_manager(),
        "evidence": f"os-release readable={OS_RELEASE_PATH.is_file()}",
    }


def _collect_ssh_config() -> dict[str, Any]:
    result: dict[str, Any] = {
        "path": str(SSH_CONFIG_PATH),
        "readable": False,
        "settings": {},
        "evidence": "",
    }
    if not SSH_CONFIG_PATH.exists():
        result["evidence"] = "sshd_config not found."
        return result
    try:
        lines = SSH_CONFIG_PATH.read_text(encoding="utf-8", errors="replace").splitlines()
    except PermissionError:
        result["evidence"] = "sshd_config permission denied or not readable."
        return result
    except OSError as exc:
        result["evidence"] = f"sshd_config not readable: {type(exc).__name__}"
        return result

    settings: dict[str, list[str]] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(None, 1)
        key = parts[0]
        value = parts[1].strip() if len(parts) > 1 else ""
        settings.setdefault(key.lower(), []).append(value)

    result["readable"] = True
    result["settings"] = {
        "PermitRootLogin": _last(settings, "permitrootlogin"),
        "PasswordAuthentication": _last(settings, "passwordauthentication"),
        "PubkeyAuthentication": _last(settings, "pubkeyauthentication"),
        "Port": _last(settings, "port"),
        "AllowUsers": settings.get("allowusers", []),
        "AllowGroups": settings.get("allowgroups", []),
        "MaxAuthTries": _last(settings, "maxauthtries"),
        "X11Forwarding": _last(settings, "x11forwarding"),
        "LoginGraceTime": _last(settings, "logingracetime"),
    }
    result["evidence"] = "sshd_config parsed successfully."
    return result


def _collect_firewall_status() -> dict[str, Any]:
    checks = []
    for command in (
        ["ufw", "status"],
        ["firewall-cmd", "--state"],
        ["iptables", "-L"],
        ["nft", "list", "ruleset"],
    ):
        checks.append(_run_readonly_command(command))
    active = _firewall_active(checks)
    return {
        "checks": checks,
        "active": active,
        "evidence": "Firewall appears active." if active else "Firewall status inactive, unavailable, or inconclusive.",
    }


def _collect_file_permissions() -> dict[str, Any]:
    tmp = [_path_mode_item(path) for path in TMP_PATHS]
    passwd = _path_mode_item(PASSWD_PATH)
    shadow = _path_mode_item(SHADOW_PATH)
    suid_files = _collect_limited_suid_files()
    return {
        "tmp_directories": tmp,
        "passwd": passwd,
        "shadow": shadow,
        "suid_scan_scope": [str(path) for path in SUID_SCAN_DIRS],
        "suid_files": suid_files,
        "unexpected_suid_files": [
            item for item in suid_files if Path(item["path"]).name not in EXPECTED_SUID_NAMES
        ],
        "evidence": "Checked limited, predefined paths only.",
    }


def _collect_accounts() -> dict[str, Any]:
    result = {
        "passwd_readable": False,
        "uid0_accounts": [],
        "interactive_system_accounts": [],
        "passwordless_sudo": [],
        "sudoers_evidence": [],
        "evidence": "",
    }
    try:
        lines = PASSWD_PATH.read_text(encoding="utf-8", errors="replace").splitlines()
    except PermissionError:
        result["evidence"] = "passwd permission denied or not readable."
        return result
    except OSError as exc:
        result["evidence"] = f"passwd not readable: {type(exc).__name__}"
        return result

    result["passwd_readable"] = True
    for line in lines:
        parts = line.split(":")
        if len(parts) < 7:
            continue
        username, _, uid, _, _, _, shell = parts[:7]
        try:
            uid_int = int(uid)
        except ValueError:
            continue
        if uid_int == 0:
            result["uid0_accounts"].append(username)
        if uid_int < 1000 and shell in {"/bin/bash", "/bin/sh", "/usr/bin/bash", "/usr/bin/sh"} and username != "root":
            result["interactive_system_accounts"].append({"user": username, "uid": uid_int, "shell": shell})

    sudo_findings, sudo_evidence = _read_sudoers()
    result["passwordless_sudo"] = sudo_findings
    result["sudoers_evidence"] = sudo_evidence
    result["evidence"] = "passwd parsed successfully."
    return result


def _run_readonly_command(command: list[str]) -> dict[str, Any]:
    executable = shutil.which(command[0])
    if not executable:
        return {"command": " ".join(command), "available": False, "returncode": None, "output": "", "error": "command not found"}
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=3,
        )
    except PermissionError:
        return {"command": " ".join(command), "available": True, "returncode": None, "output": "", "error": "permission denied"}
    except (OSError, subprocess.SubprocessError) as exc:
        return {"command": " ".join(command), "available": True, "returncode": None, "output": "", "error": type(exc).__name__}
    return {
        "command": " ".join(command),
        "available": True,
        "returncode": result.returncode,
        "output": (result.stdout or result.stderr).strip()[:1600],
        "error": "",
    }


def _firewall_active(checks: list[dict[str, Any]]) -> bool:
    for check in checks:
        output = check.get("output", "").lower()
        command = check.get("command", "")
        if command.startswith("ufw") and "status: active" in output:
            return True
        if command.startswith("firewall-cmd") and output.strip() == "running":
            return True
        if command.startswith("iptables") and ("chain input" in output or "chain forward" in output):
            return True
        if command.startswith("nft") and output:
            return True
    return False


def _path_mode_item(path: Path) -> dict[str, Any]:
    item = {"path": str(path), "exists": path.exists(), "mode": "unknown", "readable": False, "sticky_bit": False, "world_writable": False}
    try:
        path_stat = path.stat()
    except PermissionError:
        item["evidence"] = "permission denied"
        return item
    except OSError as exc:
        item["evidence"] = f"not readable: {type(exc).__name__}"
        return item
    mode = stat.S_IMODE(path_stat.st_mode)
    item["mode"] = oct(mode)
    item["readable"] = os.access(path, os.R_OK)
    item["sticky_bit"] = bool(mode & stat.S_ISVTX)
    item["world_writable"] = bool(mode & stat.S_IWOTH)
    item["evidence"] = f"mode={oct(mode)}"
    return item


def _collect_limited_suid_files() -> list[dict[str, Any]]:
    items = []
    for directory in SUID_SCAN_DIRS:
        if not directory.is_dir():
            continue
        try:
            entries = list(directory.iterdir())
        except (PermissionError, OSError):
            continue
        for entry in entries:
            try:
                entry_stat = entry.stat()
            except (PermissionError, OSError):
                continue
            if entry_stat.st_mode & stat.S_ISUID:
                items.append({"path": str(entry), "mode": oct(stat.S_IMODE(entry_stat.st_mode)), "expected": entry.name in EXPECTED_SUID_NAMES})
    return items[:200]


def _read_sudoers() -> tuple[list[dict[str, str]], list[str]]:
    matches = []
    evidence = []
    paths = [SUDOERS_PATHS[0]]
    sudoers_dir = SUDOERS_PATHS[1]
    if sudoers_dir.is_dir():
        try:
            paths.extend(path for path in sudoers_dir.iterdir() if path.is_file())
        except (PermissionError, OSError):
            evidence.append(f"{sudoers_dir} permission denied or not readable.")
    for path in paths:
        if not path.exists():
            evidence.append(f"{path} not found.")
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except PermissionError:
            evidence.append(f"{path} permission denied or not readable.")
            continue
        except OSError as exc:
            evidence.append(f"{path} not readable: {type(exc).__name__}")
            continue
        evidence.append(f"{path} read.")
        for line in lines:
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and "NOPASSWD" in stripped:
                matches.append({"path": str(path), "rule": stripped[:240]})
    return matches, evidence


def _parse_key_value_file(path: Path) -> dict[str, str]:
    values = {}
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return values
    for line in lines:
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value.strip().strip('"')
    return values


def _detect_package_manager() -> str:
    for manager in ("apt", "dnf", "yum", "pacman", "zypper", "apk"):
        if shutil.which(manager):
            return manager
    return "unknown"


def _last(settings: dict[str, list[str]], key: str) -> str | None:
    values = settings.get(key, [])
    return values[-1] if values else None

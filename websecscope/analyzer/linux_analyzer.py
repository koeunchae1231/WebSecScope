from __future__ import annotations

from typing import Any

from websecscope.guide import recommendation_for
from websecscope.models import FAIL, PASS, WARNING, Finding, RISK_HIGH, RISK_INFO, RISK_LOW, RISK_MEDIUM, build_finding


def analyze_linux_scan(linux_scan: dict[str, Any]) -> list[Finding]:
    if linux_scan.get("status") == "skipped":
        return [
            _finding(
                "LINUX_SCAN_SKIPPED",
                "Linux checks skipped",
                PASS,
                RISK_INFO,
                "Linux-specific checks were skipped because the current runtime is not Linux.",
                "; ".join(linux_scan.get("evidence", [])),
                "Run WebSecScope on the authorized Linux host to collect Linux security checks.",
            )
        ]
    if linux_scan.get("status") != "completed":
        return [
            _finding(
                "LINUX_SCAN_UNAVAILABLE",
                "Linux scan unavailable",
                WARNING,
                RISK_LOW,
                "Linux scan did not complete but the overall scan can continue.",
                "; ".join(linux_scan.get("evidence", [])) or "Linux scan unavailable.",
                recommendation_for("LINUX_SCAN_UNAVAILABLE"),
            )
        ]

    findings: list[Finding] = []
    findings.extend(_analyze_system_info(linux_scan))
    findings.extend(_analyze_ssh(linux_scan.get("ssh_config", {})))
    findings.extend(_analyze_firewall(linux_scan))
    findings.extend(_analyze_file_permissions(linux_scan.get("file_permissions", {})))
    findings.extend(_analyze_accounts(linux_scan.get("accounts", {})))
    findings.extend(_analyze_open_ports(linux_scan.get("open_ports", [])))
    return findings


def _analyze_system_info(linux_scan: dict[str, Any]) -> list[Finding]:
    info = linux_scan.get("system_info", {})
    return [
        _finding(
            "LINUX_SYSTEM_INFO",
            "Linux system context",
            PASS,
            RISK_INFO,
            "Collected Linux system context for evidence and report correlation.",
            f"OS={info.get('os_name')} {info.get('os_version')}; kernel={info.get('kernel_version')}; hostname={info.get('hostname')}; user={info.get('current_user')}; root={info.get('is_root')}; package_manager={info.get('package_manager')}",
            "No action required.",
        )
    ]


def _analyze_ssh(ssh_config: dict[str, Any]) -> list[Finding]:
    if not ssh_config.get("readable"):
        return [
            _finding(
                "LINUX_SSH_CONFIG_READABLE",
                "SSH configuration readability",
                WARNING,
                RISK_LOW,
                "sshd_config could not be read; this is often expected for non-root users.",
                ssh_config.get("evidence", "sshd_config not readable."),
                recommendation_for("LINUX_SSH_CONFIG_REVIEW"),
            )
        ]
    settings = ssh_config.get("settings", {})
    findings = []
    if _is_yes(settings.get("PermitRootLogin")):
        findings.append(_finding("LINUX_SSH_ROOT_LOGIN", "SSH root login enabled", FAIL, RISK_HIGH, "PermitRootLogin yes allows direct root authentication over SSH.", f"PermitRootLogin={settings.get('PermitRootLogin')}", recommendation_for("LINUX_SSH_ROOT_LOGIN")))
    if _is_yes(settings.get("PasswordAuthentication")):
        findings.append(_finding("LINUX_SSH_PASSWORD_AUTH", "SSH password authentication enabled", WARNING, RISK_MEDIUM, "PasswordAuthentication yes increases brute-force exposure compared with key-only access.", f"PasswordAuthentication={settings.get('PasswordAuthentication')}", recommendation_for("LINUX_SSH_PASSWORD_AUTH")))
    if _is_yes(settings.get("X11Forwarding")):
        findings.append(_finding("LINUX_SSH_X11_FORWARDING", "SSH X11 forwarding enabled", WARNING, RISK_LOW, "X11Forwarding increases attack surface for SSH sessions.", f"X11Forwarding={settings.get('X11Forwarding')}", recommendation_for("LINUX_SSH_X11_FORWARDING")))
    max_auth = _to_int(settings.get("MaxAuthTries"))
    if max_auth is None or max_auth > 6:
        findings.append(_finding("LINUX_SSH_MAX_AUTH_TRIES", "SSH MaxAuthTries review", WARNING, RISK_LOW, "Missing or high MaxAuthTries can allow more repeated authentication attempts per connection.", f"MaxAuthTries={settings.get('MaxAuthTries') or 'not set'}", recommendation_for("LINUX_SSH_MAX_AUTH_TRIES")))
    port = settings.get("Port")
    if port in {None, "22"}:
        findings.append(_finding("LINUX_SSH_PORT_DEFAULT", "SSH port context", PASS, RISK_INFO, "Default SSH port 22 is context, not a confirmed vulnerability by itself.", f"Port={port or 'not set (default 22)'}", "No action required."))
    if not settings.get("AllowUsers") and not settings.get("AllowGroups"):
        findings.append(_finding("LINUX_SSH_ALLOWLIST_REVIEW", "SSH allowlist not configured", WARNING, RISK_LOW, "AllowUsers or AllowGroups can reduce SSH account exposure when operationally appropriate.", "AllowUsers/AllowGroups not observed.", recommendation_for("LINUX_SSH_ALLOWLIST")))
    if not findings:
        findings.append(_finding("LINUX_SSH_BASELINE", "SSH configuration baseline", PASS, RISK_INFO, "No high-risk SSH configuration pattern was observed in the parsed file.", ssh_config.get("evidence", ""), "No action required."))
    return findings


def _analyze_firewall(linux_scan: dict[str, Any]) -> list[Finding]:
    firewall = linux_scan.get("firewall", {})
    ports = linux_scan.get("open_ports", [])
    if not firewall.get("active") and ports:
        return [
            _finding(
                "LINUX_FIREWALL_INCONCLUSIVE_WITH_PORTS",
                "Firewall inactive or inconclusive with listening services",
                WARNING,
                RISK_MEDIUM,
                "Firewall status could not be confirmed while listening TCP ports were observed.",
                f"firewall={firewall.get('evidence')}; ports={ports}",
                recommendation_for("LINUX_FIREWALL_REVIEW"),
            )
        ]
    return [
        _finding(
            "LINUX_FIREWALL_STATUS",
            "Firewall status",
            PASS if firewall.get("active") else WARNING,
            RISK_INFO if firewall.get("active") else RISK_LOW,
            "Firewall state was checked with available read-only tools.",
            firewall.get("evidence", "Firewall status unavailable."),
            recommendation_for("LINUX_FIREWALL_REVIEW") if not firewall.get("active") else "No action required.",
        )
    ]


def _analyze_file_permissions(file_permissions: dict[str, Any]) -> list[Finding]:
    findings = []
    bad_tmp = [item for item in file_permissions.get("tmp_directories", []) if item.get("world_writable") and not item.get("sticky_bit")]
    if bad_tmp:
        findings.append(_finding("LINUX_TMP_STICKY_BIT", "World-writable temporary directory without sticky bit", FAIL, RISK_MEDIUM, "World-writable temporary directories should use the sticky bit to prevent users from deleting each other's files.", str(bad_tmp), recommendation_for("LINUX_TMP_STICKY_BIT")))
    passwd = file_permissions.get("passwd", {})
    if passwd.get("mode") not in {"0o644", "0o444"} and passwd.get("exists"):
        findings.append(_finding("LINUX_PASSWD_PERMISSION", "passwd file permission review", WARNING, RISK_LOW, "/etc/passwd should not be writable by group or others.", f"/etc/passwd mode={passwd.get('mode')}", recommendation_for("LINUX_PASSWD_PERMISSION")))
    shadow = file_permissions.get("shadow", {})
    if shadow.get("readable"):
        findings.append(_finding("LINUX_SHADOW_READABLE", "shadow file readable by current user", WARNING, RISK_MEDIUM, "/etc/shadow readability by the scanner user may indicate elevated privileges or weak permissions.", f"/etc/shadow mode={shadow.get('mode')}; readable={shadow.get('readable')}", recommendation_for("LINUX_SHADOW_PERMISSION")))
    unexpected_suid = file_permissions.get("unexpected_suid_files", [])
    if unexpected_suid:
        findings.append(_finding("LINUX_SUID_REVIEW", "Unexpected SUID file review recommended", WARNING, RISK_MEDIUM, "SUID files in limited system directories should be reviewed; discovery is not proof of compromise.", str(unexpected_suid[:20]), recommendation_for("LINUX_SUID_REVIEW")))
    if not findings:
        findings.append(_finding("LINUX_FILE_PERMISSION_BASELINE", "File permission baseline", PASS, RISK_INFO, "No risky pattern was observed in the limited file permission checks.", file_permissions.get("evidence", ""), "No action required."))
    return findings


def _analyze_accounts(accounts: dict[str, Any]) -> list[Finding]:
    findings = []
    uid0 = [user for user in accounts.get("uid0_accounts", []) if user != "root"]
    if uid0:
        findings.append(_finding("LINUX_EXTRA_UID0_ACCOUNTS", "Additional UID 0 accounts", FAIL, RISK_HIGH, "UID 0 accounts other than root have full root privileges and should be reviewed.", f"uid0_accounts={uid0}", recommendation_for("LINUX_UID0_REVIEW")))
    interactive_system = accounts.get("interactive_system_accounts", [])
    if interactive_system:
        findings.append(_finding("LINUX_INTERACTIVE_SYSTEM_ACCOUNTS", "System accounts with interactive shells", WARNING, RISK_LOW, "Low-UID system accounts with interactive shells should be reviewed for necessity.", str(interactive_system[:20]), recommendation_for("LINUX_SYSTEM_SHELL_REVIEW")))
    nopasswd = accounts.get("passwordless_sudo", [])
    if nopasswd:
        findings.append(_finding("LINUX_PASSWORDLESS_SUDO", "Passwordless sudo rule observed", WARNING, RISK_MEDIUM, "NOPASSWD sudo rules should be tightly scoped and reviewed.", str(nopasswd[:20]), recommendation_for("LINUX_SUDO_REVIEW")))
    if not findings:
        findings.append(_finding("LINUX_ACCOUNT_BASELINE", "Account baseline", PASS, RISK_INFO, "No additional UID 0 account, interactive system account, or readable NOPASSWD sudo rule was observed.", accounts.get("evidence", ""), "No action required."))
    return findings


def _analyze_open_ports(ports: list[int]) -> list[Finding]:
    risky_ports = [port for port in ports if port not in {22, 80, 443}]
    return [
        _finding(
            "LINUX_OPEN_PORTS",
            "Open listening ports",
            WARNING if risky_ports else PASS,
            RISK_MEDIUM if risky_ports else RISK_INFO,
            "Listening TCP ports were collected from /proc/net/tcp and /proc/net/tcp6.",
            f"Listening ports: {', '.join(map(str, ports))}" if ports else "No listening TCP ports found.",
            recommendation_for("LINUX_OPEN_PORT") if risky_ports else "No action required.",
            {"ports": ports, "unexpected_ports": risky_ports},
        )
    ]


def _finding(
    check_id: str,
    title: str,
    status: str,
    risk: str,
    description: str,
    evidence: str,
    recommendation: str,
    metadata: dict[str, Any] | None = None,
) -> Finding:
    return build_finding(
        check_id,
        "linux",
        title,
        status,
        risk,
        evidence,
        recommendation,
        description=description,
        metadata=metadata,
    )


def _is_yes(value: Any) -> bool:
    return str(value).strip().lower() == "yes"


def _to_int(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None

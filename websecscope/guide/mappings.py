DEFAULT_RECOMMENDATION = "Review the finding and apply the least-privilege secure configuration recommended by the service vendor."

GUIDES = {
    "WEB_HEADER_MISSING": "Add the missing HTTP security header at the web server, reverse proxy, or application layer.",
    "WEB_COOKIE_FLAGS": "Set Secure, HttpOnly, and SameSite attributes on session and sensitive cookies.",
    "WEB_SENSITIVE_PATH": "Remove public exposure for administrative, repository, backup, and configuration paths.",
    "LINUX_OPEN_PORT": "Close unused ports or restrict access with host firewall rules and network security groups.",
    "LINUX_SCAN_UNAVAILABLE": "Run the scanner on the Linux host or provide collected host data for offline analysis.",
    "LINUX_SSH_CONFIG_REVIEW": "Run the scanner with sufficient read access or review sshd_config manually for secure SSH settings.",
    "LINUX_SSH_ROOT_LOGIN": "Set PermitRootLogin to no or prohibit-password and use named administrative accounts with sudo.",
    "LINUX_SSH_PASSWORD_AUTH": "Prefer PubkeyAuthentication and disable PasswordAuthentication where operationally possible.",
    "LINUX_SSH_X11_FORWARDING": "Disable X11Forwarding unless it is explicitly required.",
    "LINUX_SSH_MAX_AUTH_TRIES": "Set a conservative MaxAuthTries value such as 3 to 6.",
    "LINUX_SSH_ALLOWLIST": "Consider AllowUsers or AllowGroups to limit which accounts can authenticate with SSH.",
    "LINUX_FIREWALL_REVIEW": "Enable and verify host firewall policy with ufw, firewalld, iptables, nftables, or cloud security groups.",
    "LINUX_TMP_STICKY_BIT": "Set the sticky bit on world-writable temporary directories, for example chmod 1777 /tmp.",
    "LINUX_PASSWD_PERMISSION": "Keep /etc/passwd owned by root and not writable by group or others, commonly mode 0644.",
    "LINUX_SHADOW_PERMISSION": "Restrict /etc/shadow readability to root or the shadow group according to distro policy.",
    "LINUX_SUID_REVIEW": "Review unexpected SUID binaries in limited system paths and remove the bit when not required.",
    "LINUX_UID0_REVIEW": "Remove or justify any UID 0 account other than root.",
    "LINUX_SYSTEM_SHELL_REVIEW": "Use nologin or false shells for system accounts that do not require interactive login.",
    "LINUX_SUDO_REVIEW": "Review NOPASSWD sudo rules and scope them to the smallest command set possible.",
    "DOCKER_ROOT_USER": "Run containers with a non-root USER and drop unnecessary Linux capabilities.",
    "DOCKER_PRIVILEGED": "Avoid privileged containers; use specific device or capability grants only when required.",
    "DOCKER_LATEST_TAG": "Pin container images to immutable versions or digests instead of using the latest tag.",
    "DOCKER_SECRET_ENV": "Move secrets from environment variables to a secret manager or Docker/Kubernetes secrets.",
    "DOCKER_SCAN_UNAVAILABLE": "Install Docker CLI access or run the scanner on a Docker host for container checks.",
    "DOCKER_IMAGE_TAG": "Use explicit image tags and avoid latest or untagged images in production deployments.",
    "DOCKER_DIGEST_PINNING": "Pin images by digest for critical workloads where reproducibility and supply-chain control matter.",
    "DOCKER_HOST_NETWORK": "Avoid host network mode unless explicitly required and protected by host-level controls.",
    "DOCKER_HOST_NAMESPACE": "Avoid host PID or IPC namespace sharing unless there is a documented operational need.",
    "DOCKER_READONLY_ROOTFS": "Enable read-only root filesystems and mount writable paths explicitly where needed.",
    "DOCKER_RISKY_CAPS": "Remove high-risk added capabilities and grant only the smallest capability set required.",
    "DOCKER_CAP_DROP": "Drop unused Linux capabilities, ideally starting with ALL and adding back only what is required.",
    "DOCKER_SOCKET_MOUNT": "Do not mount /var/run/docker.sock into containers unless the container is a tightly controlled Docker management component.",
    "DOCKER_SENSITIVE_MOUNT": "Review sensitive host path mounts and replace broad mounts with narrow read-only paths when possible.",
    "DOCKER_EXTERNAL_PORTS": "Bind container ports to trusted interfaces or protect them with firewall and reverse proxy controls.",
    "DOCKER_DB_EXTERNAL": "Keep database and cache containers on private networks and avoid binding them to public interfaces.",
    "CVE_ANALYSIS": "Review service versions against vendor advisories and patch vulnerable packages promptly.",
    "API_DOCS_EXPOSED": "Restrict API documentation to trusted networks or authenticated developer/admin users.",
    "API_ADMIN_PATH_EXPOSED": "Protect administrative routes with strong authentication, authorization checks, and network restrictions.",
    "AUTH_MAY_BE_MISSING": "Require authentication and object-level authorization for non-public API endpoints.",
    "JWT_REVIEW": "Use signed JWTs with a strong algorithm, short expiration, and no sensitive personal or secret data in payloads.",
    "CORS_WILDCARD_CREDENTIALS": "Do not combine wildcard CORS origins with credentials; allow only explicit trusted origins.",
    "CORS_ORIGIN_REFLECTION": "Validate Origin against an allowlist instead of reflecting arbitrary Origin values.",
    "CORS_WILDCARD": "Review whether wildcard CORS is necessary and limit it to public, non-sensitive resources.",
    "IDOR_REVIEW": "Review numeric object identifier routes for object-level authorization checks.",
    "RATE_LIMIT_HEADERS": "Apply rate limiting to authentication endpoints and expose standard retry or rate-limit headers where appropriate.",
    "SERVICE_RISKY_EXPOSURE": "Restrict this service to trusted networks, bind it to private interfaces when possible, and require strong authentication.",
    "SERVICE_SSH_REVIEW": "Review the SSH protocol and product version, disable obsolete protocol support, and patch OpenSSH if it is outdated.",
    "SERVICE_VERSION_UNKNOWN": "Collect package inventory or safe service banners so later CVE/CVSS analysis can match product and version accurately.",
    "CVE_REVIEW": "Verify whether the detected product/version and deployment configuration are affected, then prioritize vendor patches or mitigations by CVSS severity.",
}


def recommendation_for(key: str) -> str:
    return GUIDES.get(key, DEFAULT_RECOMMENDATION)


def recommendation_for_finding(check_id: str, category: str) -> str:
    if check_id in GUIDES:
        return GUIDES[check_id]
    for prefix in (
        "WEB_",
        "API_",
        "AUTH_",
        "JWT_",
        "CORS_",
        "IDOR_",
        "RATE_LIMIT_",
        "SERVICE_",
        "CVE_",
        "LINUX_",
        "DOCKER_",
    ):
        if check_id.startswith(prefix):
            fallback = GUIDES.get(prefix.rstrip("_"))
            if fallback:
                return fallback
    category_defaults = {
        "web": "Review the web finding and apply the corresponding secure header or exposure control.",
        "api": "Review API exposure and require authentication or access control where appropriate.",
        "auth": "Review authentication and authorization controls for the affected endpoint.",
        "jwt": "Review JWT signing, expiration, and payload content.",
        "cors": "Review CORS origin and credential policy against a strict allowlist.",
        "idor": "Review object-level authorization for ID-based routes.",
        "rate_limit": "Review throttling controls for authentication and sensitive endpoints.",
        "service": "Review exposed services and restrict unnecessary network access.",
        "cve": "Verify CVE applicability before prioritizing patching or mitigation.",
        "linux": "Review Linux hardening guidance for the affected control.",
        "docker": "Review Docker runtime hardening for the affected container setting.",
    }
    return category_defaults.get(category, DEFAULT_RECOMMENDATION)

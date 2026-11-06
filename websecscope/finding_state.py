"""Execution state shared by scoring and report summaries; never infer from prose."""
from typing import Any


def skip_reason(check_id: str, metadata: dict[str, Any]) -> str | None:
    if metadata.get("skipped") is True:
        return "metadata.skipped"
    if check_id in {"LINUX_SCAN_SKIPPED", "DOCKER_SCAN_SKIPPED"}:
        return "legacy_skipped_check_id"
    return None


def dict_skip_reason(finding: dict[str, Any]) -> str | None:
    return skip_reason(finding.get("check_id", finding.get("id", "")), finding.get("metadata") or {})

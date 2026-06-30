from __future__ import annotations

from typing import Any


def summarize_changes(changes: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "improved": _count(changes, "IMPROVED"),
        "regressed": _count(changes, "REGRESSED"),
        "changed": _count(changes, "CHANGED"),
        "new": _count(changes, "NEW"),
        "resolved": _count(changes, "RESOLVED"),
        "unchanged": _count(changes, "UNCHANGED"),
    }


def _count(changes: list[dict[str, Any]], state: str) -> int:
    return sum(1 for change in changes if change["state"] == state)

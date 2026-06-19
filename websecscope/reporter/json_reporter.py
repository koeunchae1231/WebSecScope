from __future__ import annotations

from pathlib import Path

from websecscope.models import ScanResult
from websecscope.utils import save_json


def write_json_report(result: ScanResult, output_path: str | Path) -> Path:
    return save_json(output_path, result.to_dict())

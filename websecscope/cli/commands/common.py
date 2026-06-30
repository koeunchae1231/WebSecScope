from __future__ import annotations

import json
from typing import Any

from websecscope.utils import load_json


def safe_load_json(path: str) -> dict[str, Any] | None:
    try:
        return load_json(path)
    except FileNotFoundError:
        print(f"Input JSON not found: {path}")
    except json.JSONDecodeError:
        print(f"Input JSON is not valid: {path}")
    except OSError as exc:
        print(f"Input JSON could not be read: {path} ({type(exc).__name__})")
    return None

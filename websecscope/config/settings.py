from __future__ import annotations

import os
from dataclasses import dataclass


DEFAULT_OLLAMA_URL = "http://localhost:11434/api/generate"
DEFAULT_OLLAMA_MODEL = "qwen2.5:7b"
DEFAULT_OLLAMA_TIMEOUT = 60
DEFAULT_OLLAMA_TEMPERATURE = 0.2

ENV_OLLAMA_URL = "WEBSECSCOPE_OLLAMA_URL"
ENV_OLLAMA_MODEL = "WEBSECSCOPE_OLLAMA_MODEL"
ENV_OLLAMA_TIMEOUT = "WEBSECSCOPE_OLLAMA_TIMEOUT"
ENV_OLLAMA_TEMPERATURE = "WEBSECSCOPE_OLLAMA_TEMPERATURE"


@dataclass(frozen=True)
class Settings:
    ollama_url: str = DEFAULT_OLLAMA_URL
    ollama_model: str = DEFAULT_OLLAMA_MODEL
    ollama_timeout: int = DEFAULT_OLLAMA_TIMEOUT
    ollama_temperature: float = DEFAULT_OLLAMA_TEMPERATURE


def load_settings() -> Settings:
    return Settings(
        ollama_url=os.getenv(ENV_OLLAMA_URL, DEFAULT_OLLAMA_URL),
        ollama_model=os.getenv(ENV_OLLAMA_MODEL, DEFAULT_OLLAMA_MODEL),
        ollama_timeout=_env_int(ENV_OLLAMA_TIMEOUT, DEFAULT_OLLAMA_TIMEOUT),
        ollama_temperature=_env_float(
            ENV_OLLAMA_TEMPERATURE,
            DEFAULT_OLLAMA_TEMPERATURE,
        ),
    )


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


_SETTINGS = load_settings()

OLLAMA_URL = _SETTINGS.ollama_url
OLLAMA_MODEL = _SETTINGS.ollama_model
OLLAMA_TIMEOUT = _SETTINGS.ollama_timeout
OLLAMA_TEMPERATURE = _SETTINGS.ollama_temperature

"""Server exposes arbitrary env access (LLM-controlled key) — Tier 2."""
import os


def read_env(varname: str) -> str | None:
    return os.environ.get(varname)


def list_all_env() -> dict:
    return dict(os.environ)

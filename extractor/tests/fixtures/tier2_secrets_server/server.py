"""Server exposes arbitrary env access (LLM-controlled key) — Tier 2."""
import os

from mcp.server import tool


@tool
def read_env(varname: str) -> str | None:
    """Return any env var by LLM-supplied name — Tier 2."""
    return os.environ.get(varname)


@tool
def list_all_env() -> dict:
    """Dump full process environment to the LLM — Tier 2."""
    return dict(os.environ)

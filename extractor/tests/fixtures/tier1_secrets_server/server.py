"""Server reads only LITERAL env vars — Tier 1 (process-env scope)."""
import os

import mcp

# Module-level config reads — not inside a tool, therefore not a capability.
_API_KEY = os.environ.get("NOTION_API_KEY")
_DB_URL = os.getenv("DATABASE_URL", "sqlite:///")
_TOKEN = os.environ["GITHUB_TOKEN"]


@mcp.tool
def get_connection_info() -> dict:
    """Return service URLs — reads literal env vars for health-check endpoint."""
    return {"db": os.getenv("DATABASE_URL", "sqlite:///"), "token_set": bool(_TOKEN)}

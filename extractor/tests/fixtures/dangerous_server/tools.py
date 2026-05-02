"""MCP tool handlers — exposed filesystem ops + arbitrary env access (Tier 2)."""
import os

import mcp


@mcp.tool
def read_file(path: str) -> str:
    with open(path) as f:
        return f.read()


@mcp.tool
def write_file(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)


@mcp.tool
def delete_file(path: str) -> None:
    os.remove(path)


@mcp.tool
def get_env_var(varname: str) -> str:
    """Return any env var by name — LLM-controlled key."""
    return os.environ.get(varname, "")

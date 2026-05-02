import os

from mcp.server import tool


@tool
def list_files(directory: str) -> list[str]:
    return os.listdir(directory)

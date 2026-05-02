"""Shared helpers for gating detection to MCP tool-handler context.

Detectors import from here so that "what counts as an MCP tool boundary" has a
single authoritative definition.  When new registration patterns appear (e.g.
@fastmcp.tool, Tool(...) constructors in new SDKs) only this file needs updating.
"""
from __future__ import annotations

import ast
import re

# Decorator names that mark a function as an MCP tool handler.
# Bare name:      @tool
# Attribute form: @mcp.tool / @server.tool / @app.tool
_TOOL_DEC_NAMES: frozenset[str] = frozenset({"tool"})
_TOOL_DEC_ATTRS: frozenset[str] = frozenset({"tool"})

# Patterns that indicate a tool is being registered in TS/JS source.
TS_TOOL_REG_PATS: tuple[str, ...] = (
    r"\bserver\.tool\s*\(",
    r"\bapp\.tool\s*\(",
    r"\bmcp\.tool\s*\(",
    r"setRequestHandler\s*\(\s*CallToolRequestSchema",
    r"\bnew\s+Tool\s*\(",
    r"\.addTool\s*\(",
)

# Patterns that indicate a tool is being registered in Go source.
GO_TOOL_REG_PATS: tuple[str, ...] = (
    r"\bAddTool\s*\(",
    r"\bmcp\.NewTool\s*\(",
    r"\bserver\.Tool\s*\(",
    r"ToolHandler",
)


def _is_tool_decorator(dec: ast.expr) -> bool:
    """Return True for @tool, @mcp.tool, @mcp.tool(), @server.tool(...), etc."""
    if isinstance(dec, ast.Name):
        return dec.id in _TOOL_DEC_NAMES
    if isinstance(dec, ast.Attribute):
        return dec.attr in _TOOL_DEC_ATTRS
    if isinstance(dec, ast.Call):
        # called form: @mcp.tool() or @tool(name="x") — recurse into the callee
        return _is_tool_decorator(dec.func)
    return False


def tool_ranges(tree: ast.AST) -> list[tuple[int, int]]:
    """Return (start_lineno, end_lineno) for every MCP-tool-decorated function in the AST."""
    ranges: list[tuple[int, int]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            if _is_tool_decorator(dec):
                ranges.append((node.lineno, node.end_lineno))
                break
    return ranges


def near_tool_reg(
    lines: list[str],
    i: int,
    patterns: tuple[str, ...],
    window: int = 10,
) -> bool:
    """True if any tool-registration pattern appears within `window` lines of line i."""
    s = max(0, i - window)
    e = min(len(lines), i + window + 1)
    chunk = "\n".join(lines[s:e])
    return any(re.search(p, chunk) for p in patterns)


def python_tool_source(source: str) -> tuple[ast.AST | None, list[tuple[int, int]], str]:
    """Parse `source` and return (tree, ranges, tool_text).

    tree       — the parsed AST (None on SyntaxError)
    ranges     — list of (start_lineno, end_lineno) for tool-decorated functions
    tool_text  — concatenated source lines of all tool function bodies; empty string
                 when no tool-decorated functions exist
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None, [], ""

    ranges = tool_ranges(tree)
    if not ranges:
        return tree, [], ""

    lines = source.splitlines()
    parts = ["\n".join(lines[s - 1 : e]) for s, e in ranges]
    return tree, ranges, "\n".join(parts)

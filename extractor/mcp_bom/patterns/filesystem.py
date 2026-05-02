from __future__ import annotations

import ast
import re
from pathlib import Path

from mcp_bom._tool_scope import GO_TOOL_REG_PATS, TS_TOOL_REG_PATS, near_tool_reg, python_tool_source
from mcp_bom.models import Confidence, FilesystemResult

_PYTHON_PATTERNS = {
    "read": [
        r"\bopen\s*\(",
        r"\bpathlib\.Path\b",
        r"\bos\.path\b",
        r"\baiofiles\b",
        r"\bos\.listdir\b",
        r"\bos\.walk\b",
        r"\bglob\.glob\b",
        r"\bos\.stat\b",
    ],
    "write": [
        r"\bshutil\.copy\b",
        r"\bshutil\.move\b",
        r"\bos\.makedirs\b",
        r"\bos\.rename\b",
        r"\btempfile\.mkstemp\b",
    ],
    "delete": [
        r"\bos\.remove\b",
        r"\bos\.unlink\b",
        r"\bshutil\.rmtree\b",
    ],
}

_TS_PATTERNS = {
    "read": [
        r"\bfs\.read",
        r"\breadFile\b",
        r"\bcreateReadStream\b",
        r"\bfs\.readdir\b",
        r"\bfs\.stat\b",
    ],
    "write": [
        r"\bfs\.write",
        r"\bwriteFile\b",
        r"\bcreateWriteStream\b",
        r"\bfs\.mkdir\b",
        r"\bfs\.rename\b",
    ],
    "delete": [
        r"\bfs\.unlink\b",
        r"\bfs\.rmdir\b",
        r"\bfs\.rm\b",
    ],
}

_GO_PATTERNS = {
    "read": [
        r"\bos\.Open\b",
        r"\bos\.ReadFile\b",
        r"\bioutil\.ReadFile\b",
    ],
    "write": [
        r"\bos\.WriteFile\b",
        r"\bioutil\.WriteFile\b",
    ],
    "delete": [
        r"\bos\.Remove\b",
        r"\bos\.RemoveAll\b",
    ],
}

_SCHEMA_HEURISTICS = [
    r'"path"',
    r'"filename"',
    r'"directory"',
    r'"file_url"',
    r'"file_path"',
    r'"filepath"',
]

_SCOPE_PATTERNS = {
    "system-wide": [r"\b/usr\b", r"\b/etc\b", r"\bC:\\", r"\b/var\b", r"\bos\.path\.expanduser\b"],
    "user-home": [r"\b~/", r"\bHome\b", r"\bexpanduser\b"],
    "arbitrary": [r"\bany\s+path\b", r"\barbitrary\b"],
}


def _scan_text(content: str, patterns: dict[str, list[str]]) -> tuple[dict[str, list[str]], list[str]]:
    hits: dict[str, list[str]] = {}
    all_matches: list[str] = []
    for category, pats in patterns.items():
        for pat in pats:
            found = re.findall(pat, content, re.IGNORECASE)
            if found:
                hits.setdefault(category, []).extend(found)
                all_matches.extend(found)
    return hits, all_matches


def _scan_schema(content: str) -> list[str]:
    matches = []
    for pat in _SCHEMA_HEURISTICS:
        found = re.findall(pat, content, re.IGNORECASE)
        matches.extend(found)
    return matches


def _detect_scope(content: str) -> str:
    for scope, pats in _SCOPE_PATTERNS.items():
        for pat in pats:
            if re.search(pat, content, re.IGNORECASE):
                return scope
    return "cwd-only"


def _ast_python_filesystem(source: str) -> tuple[dict[str, list[str]], str]:
    """Return (hits, tool_text).

    hits      — filesystem call sites found inside tool-decorated functions only.
    tool_text — concatenated source of all tool function bodies (for subsequent
                regex scan); empty string when no tool-decorated functions exist.

    Import-level signals (e.g. `import shutil`) are intentionally excluded — they
    are module-level and cannot appear inside a tool-decorated function body.
    """
    empty: dict[str, list[str]] = {"read": [], "write": [], "delete": []}

    tree, ranges, tool_text = python_tool_source(source)
    if tree is None or not ranges:
        return empty, ""

    hits: dict[str, list[str]] = {"read": [], "write": [], "delete": []}
    read_calls = {"open"}
    write_calls = {"makedirs", "rename"}
    delete_calls = {"remove", "unlink"}

    def in_tool(lineno: int) -> bool:
        return any(s <= lineno <= e for s, e in ranges)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        lineno = getattr(node, "lineno", None)
        if lineno is None or not in_tool(lineno):
            continue
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        if func_name in read_calls:
            hits["read"].append(func_name)
        if func_name in write_calls:
            hits["write"].append(func_name)
        if func_name in delete_calls:
            hits["delete"].append(func_name)

    return hits, tool_text


def detect(
    source_files: dict[str, str],
) -> FilesystemResult:
    result = FilesystemResult(detected=False)
    evidence: list[str] = []
    ast_hits: dict[str, list[str]] = {"read": [], "write": [], "delete": []}

    for path, content in source_files.items():
        if path.endswith(".py"):
            ast_h, tool_text = _ast_python_filesystem(content)
            for k, v in ast_h.items():
                ast_hits[k].extend(v)
            if tool_text:
                regex_h, regex_m = _scan_text(tool_text, _PYTHON_PATTERNS)
                for k, v in regex_h.items():
                    ast_hits.setdefault(k, []).extend(v)
                evidence.extend(regex_m)
                schema_matches = _scan_schema(tool_text)
                evidence.extend(schema_matches)
        elif path.endswith((".ts", ".js", ".tsx", ".jsx")):
            ts_lines = content.splitlines()
            tool_lines = [
                line for i, line in enumerate(ts_lines)
                if near_tool_reg(ts_lines, i, TS_TOOL_REG_PATS)
            ]
            if tool_lines:
                tool_text = "\n".join(tool_lines)
                regex_h, regex_m = _scan_text(tool_text, _TS_PATTERNS)
                for k, v in regex_h.items():
                    ast_hits.setdefault(k, []).extend(v)
                evidence.extend(regex_m)
                schema_matches = _scan_schema(tool_text)
                evidence.extend(schema_matches)
        elif path.endswith(".go"):
            go_lines = content.splitlines()
            tool_lines = [
                line for i, line in enumerate(go_lines)
                if near_tool_reg(go_lines, i, GO_TOOL_REG_PATS)
            ]
            if tool_lines:
                tool_text = "\n".join(tool_lines)
                regex_h, regex_m = _scan_text(tool_text, _GO_PATTERNS)
                for k, v in regex_h.items():
                    ast_hits.setdefault(k, []).extend(v)
                evidence.extend(regex_m)

    has_read = bool(ast_hits.get("read"))
    has_write = bool(ast_hits.get("write"))
    has_delete = bool(ast_hits.get("delete"))

    if has_read or has_write or has_delete:
        result.detected = True
        result.read = has_read
        result.write = has_write
        result.delete = has_delete
        result.confidence = Confidence.HIGH if (has_read and has_write) else Confidence.MEDIUM
    elif evidence:
        result.detected = True
        result.confidence = Confidence.LOW

    if result.detected:
        all_content = "\n".join(source_files.values())
        result.scope = _detect_scope(all_content)

    result.evidence = sorted(set(evidence))[:20]
    return result

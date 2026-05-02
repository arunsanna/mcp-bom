"""Secrets capability detector with Tier 1 (config) vs Tier 2 (exposed) split.

Per issue #17:
  - Tier 1 (config): server reads a *named* env var for its OWN configuration
                     (e.g., os.environ.get("NOTION_API_KEY"), process.env.FOO).
                     This is benign and routine.
  - Tier 2 (exposed): server reads the env *generically* (full dict, dynamic key,
                      subscript with non-literal). This is "secrets gateway"-shaped
                      and is what the score function should weight heavily.

The classification matters because nearly every server has Tier 1, but only a
small fraction expose Tier 2. Conflating them inflates H14 (drift rate).
"""
from __future__ import annotations

import ast
import re

from mcp_bom._strip import language_for_path, strip_comments_and_strings
from mcp_bom._tool_scope import GO_TOOL_REG_PATS, TS_TOOL_REG_PATS, near_tool_reg, python_tool_source
from mcp_bom.models import Confidence, SecretsResult

SCHEMA_PATTERNS = [
    r'"api_key"',
    r'"token"',
    r'"secret"',
    r'"password"',
    r'"credential"',
]


def _ast_python(source: str, scope: str = "code") -> tuple[bool, bool, bool, list[str]]:
    tier1 = False
    tier2 = False
    write_seen = False
    evidence: list[str] = []

    tree, ranges, tool_text = python_tool_source(source)
    if tree is None:
        return tier1, tier2, write_seen, evidence

    if scope == "tool" and not ranges:
        return tier1, tier2, write_seen, evidence

    scan_text = tool_text if scope == "tool" else source

    def _in_scope(lineno: int) -> bool:
        if scope == "code":
            return True
        return any(s <= lineno <= e for s, e in ranges)

    for node in ast.walk(tree):
        lineno = getattr(node, "lineno", None)
        if lineno is None or not _in_scope(lineno):
            continue

        # os.environ.get(X)  /  os.getenv(X)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            mod = node.func.value.id if isinstance(node.func.value, ast.Name) else None
            attr = node.func.attr
            if (mod == "os" and attr == "getenv") or (
                isinstance(node.func.value, ast.Attribute)
                and node.func.value.attr == "environ"
                and attr == "get"
            ):
                arg0 = node.args[0] if node.args else None
                if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                    tier1 = True
                    evidence.append(f"tier1:{mod or 'os'}.{attr}({arg0.value!r})")
                else:
                    tier2 = True
                    evidence.append(f"tier2:{mod or 'os'}.{attr}(non-literal)")

        # os.environ[X]  /  os.environ[X] = Y
        if isinstance(node, ast.Subscript):
            val = node.value
            if (
                isinstance(val, ast.Attribute)
                and val.attr == "environ"
                and isinstance(val.value, ast.Name)
                and val.value.id == "os"
            ):
                key = node.slice
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    tier1 = True
                    evidence.append(f"tier1:os.environ[{key.value!r}]")
                else:
                    tier2 = True
                    evidence.append("tier2:os.environ[non-literal]")

        # assignment to os.environ[X] or os.environ.update(...)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if (
                node.func.attr in ("update", "setdefault", "pop")
                and isinstance(node.func.value, ast.Attribute)
                and node.func.value.attr == "environ"
            ):
                write_seen = True
                evidence.append(f"write:os.environ.{node.func.attr}")

        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if (
                    isinstance(tgt, ast.Subscript)
                    and isinstance(tgt.value, ast.Attribute)
                    and tgt.value.attr == "environ"
                ):
                    write_seen = True
                    evidence.append("write:os.environ[]=")

    # Bare os.environ (dict view, **os.environ, etc.) — only inside tool functions.
    if re.search(
        r"\bos\.environ\b(?!\s*\.\s*(get|setdefault|pop|update)\b|\s*\[)", scan_text
    ):
        tier2 = True
        evidence.append("tier2:os.environ-bare")

    return tier1, tier2, write_seen, evidence



def _ts_js(masked: str, scope: str = "code") -> tuple[bool, bool, bool, list[str]]:
    tier1 = False
    tier2 = False
    write_seen = False
    evidence: list[str] = []

    lines = masked.splitlines()
    for i, line in enumerate(lines):
        if scope == "tool" and not near_tool_reg(lines, i, TS_TOOL_REG_PATS):
            continue
        if re.search(r"\bprocess\.env\.[A-Z_][A-Z0-9_]*\b", line):
            tier1 = True
            evidence.append("tier1:process.env.LITERAL")
        if re.search(r"\bprocess\.env\[", line):
            tier2 = True
            evidence.append("tier2:process.env[]")
        if re.search(r"\bprocess\.env\b(?!\s*\.\s*[A-Za-z_]|\s*\[)", line):
            tier2 = True
            evidence.append("tier2:process.env-bare")
        if re.search(r"\bprocess\.env\[[^\]]+\]\s*=", line):
            write_seen = True
            evidence.append("write:process.env[]=")

    return tier1, tier2, write_seen, evidence


def _go(masked: str, scope: str = "code") -> tuple[bool, bool, bool, list[str]]:
    tier1 = False
    tier2 = False
    write_seen = False
    evidence: list[str] = []

    lines = masked.splitlines()
    for i, line in enumerate(lines):
        if scope == "tool" and not near_tool_reg(lines, i, GO_TOOL_REG_PATS):
            continue
        if re.search(r'\bos\.Getenv\s*\(\s*"[A-Za-z_][A-Za-z0-9_]*"\s*\)', line):
            tier1 = True
            evidence.append("tier1:os.Getenv(literal)")
        if re.search(r"\bos\.Getenv\s*\(\s*[A-Za-z_]", line):
            tier2 = True
            evidence.append("tier2:os.Getenv(var)")
        if re.search(r"\bos\.Environ\s*\(\s*\)", line):
            tier2 = True
            evidence.append("tier2:os.Environ()")
        if re.search(r"\bos\.Setenv\b", line):
            write_seen = True
            evidence.append("write:os.Setenv")

    return tier1, tier2, write_seen, evidence


def _kms_or_keychain(masked: str, language: str) -> str | None:
    if re.search(r"\bkeyring\b", masked):
        return "system-keychain"
    kms_pats = [
        r"\bSecretsManager\b",
        r"\bsecretsmanager\b",
        r"\bsecret_manager\b",
        r"\bkeyvault\b",
        r"\bget_secret_value\b",
    ]
    for pat in kms_pats:
        if re.search(pat, masked):
            return "cloud-kms"
    return None


def detect(source_files: dict[str, str], scope: str = "code") -> SecretsResult:
    result = SecretsResult(detected=False)
    evidence: list[str] = []
    tier1_seen = False
    tier2_seen = False
    write_seen = False
    kms_or_keychain_scope: str | None = None
    schema_hits = False

    for path, content in source_files.items():
        lang = language_for_path(path)
        masked = strip_comments_and_strings(content, lang)

        for pat in SCHEMA_PATTERNS:
            if re.search(pat, masked, re.IGNORECASE):
                schema_hits = True
                evidence.append(f"schema:{pat}")

        if lang == "python":
            t1, t2, w, ev = _ast_python(content, scope=scope)
        elif lang == "typescript":
            t1, t2, w, ev = _ts_js(masked, scope=scope)
        elif lang == "go":
            t1, t2, w, ev = _go(masked, scope=scope)
        else:
            continue

        tier1_seen = tier1_seen or t1
        tier2_seen = tier2_seen or t2
        write_seen = write_seen or w
        evidence.extend(ev)

        kms_scope = _kms_or_keychain(masked, lang)
        if kms_scope and not kms_or_keychain_scope:
            kms_or_keychain_scope = kms_scope
            evidence.append(f"scope:{kms_scope}")

    if not (tier1_seen or tier2_seen or write_seen or kms_or_keychain_scope or schema_hits):
        return result

    result.detected = True

    if tier1_seen or tier2_seen or write_seen or kms_or_keychain_scope:
        result.confidence = Confidence.HIGH
    elif schema_hits:
        result.confidence = Confidence.LOW

    result.read = tier1_seen or tier2_seen or kms_or_keychain_scope is not None
    result.write = write_seen

    if kms_or_keychain_scope == "cloud-kms":
        result.scope = "cloud-kms"
    elif kms_or_keychain_scope == "system-keychain":
        result.scope = "system-keychain"
    elif tier2_seen:
        result.scope = "arbitrary-env"
    elif tier1_seen:
        result.scope = "process-env"
    elif schema_hits:
        result.scope = "schema-only"
    else:
        result.scope = "unknown"

    result.evidence = sorted(set(evidence))[:20]
    return result

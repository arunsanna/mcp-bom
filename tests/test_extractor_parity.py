"""Anchor parity tests: port extractor (scope=code) must match spike output.

Uses the same 5 reference servers the spike was run on:
  - mcp-filesystem, mcp-fetch, mcp-everything (official MCP servers repo)
  - mcp-shell-server (tumf/mcp-shell-server Python)
  - notion-mcp-server (makenotion/notion-mcp-server)

These repos are cloned/extracted into /tmp/mcp-bom-anchors/ by the
module-scoped fixture. If the dirs already exist (e.g. from a prior run)
the clone is skipped.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from mcp_bom.extractor import extract

CATEGORIES_8 = [
    "filesystem", "shell", "egress", "ingress",
    "secrets", "delegation", "impersonation", "data_sensitivity",
]

VAL_DIR = Path(__file__).resolve().parent.parent / "validation" / "parity_check"
ANCHOR_ROOT = Path("/tmp/mcp-bom-anchors")

ANCHORS = {
    "mcp-filesystem": "mcp-servers/src/filesystem",
    "mcp-fetch": "mcp-servers/src/fetch",
    "mcp-everything": "mcp-servers/src/everything",
    "mcp-shell-server": "mcp-shell-server-py",
    "notion-mcp-server": "notion-mcp-server",
}


def _clone_once(name: str, url: str) -> Path:
    dest = ANCHOR_ROOT / name
    if dest.exists():
        return dest
    ANCHOR_ROOT.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "clone", "--depth", "1", url, str(dest)],
        check=True, capture_output=True, timeout=120,
    )
    return dest


@pytest.fixture(scope="module", autouse=True)
def _ensure_anchors():
    _clone_once("mcp-servers", "https://github.com/modelcontextprotocol/servers.git")
    _clone_once("mcp-shell-server-py", "https://github.com/tumf/mcp-shell-server.git")
    _clone_once("notion-mcp-server", "https://github.com/makenotion/notion-mcp-server.git")


def _detected_categories(report) -> set[str]:
    return {
        c for c in CATEGORIES_8
        if getattr(report.capability_vector, c).detected
    }


def _spike_expected(server_id: str) -> set[str]:
    path = VAL_DIR / f"{server_id}.spike.json"
    spike = json.loads(path.read_text())
    cv = spike["capability_vector"]
    return {c for c in CATEGORIES_8 if cv.get(c, False)}


@pytest.mark.parametrize("server_id,rel_path", list(ANCHORS.items()))
def test_anchor_parity_code_scope(server_id: str, rel_path: str):
    source = ANCHOR_ROOT / rel_path
    if not source.exists():
        pytest.skip(f"Anchor source not found: {source}")
    report = extract(str(source), server_id=server_id, scope="code")
    detected = _detected_categories(report)
    expected = _spike_expected(server_id)
    assert detected == expected, (
        f"{server_id}: detected={sorted(detected)} expected={sorted(expected)} "
        f"missing={sorted(expected - detected)} extra={sorted(detected - expected)}"
    )


@pytest.mark.parametrize("server_id,rel_path", list(ANCHORS.items()))
def test_tool_scope_is_subset_of_code_scope(server_id: str, rel_path: str):
    source = ANCHOR_ROOT / rel_path
    if not source.exists():
        pytest.skip(f"Anchor source not found: {source}")
    code_report = extract(str(source), server_id=server_id, scope="code")
    tool_report = extract(str(source), server_id=f"{server_id}-tool", scope="tool")
    code_detected = _detected_categories(code_report)
    tool_detected = _detected_categories(tool_report)
    assert tool_detected <= code_detected, (
        f"{server_id}: tool scope detected categories that code scope did not: "
        f"{sorted(tool_detected - code_detected)}"
    )


def test_tool_scope_fewer_than_code():
    source = ANCHOR_ROOT / ANCHORS["mcp-shell-server"]
    if not source.exists():
        pytest.skip("Anchor source not found")
    code_report = extract(str(source), server_id="shell-code", scope="code")
    tool_report = extract(str(source), server_id="shell-tool", scope="tool")
    code_n = sum(1 for c in CATEGORIES_8 if getattr(code_report.capability_vector, c).detected)
    tool_n = sum(1 for c in CATEGORIES_8 if getattr(tool_report.capability_vector, c).detected)
    assert tool_n < code_n, (
        f"tool scope should detect strictly fewer categories than code scope: "
        f"tool={tool_n} code={code_n}"
    )

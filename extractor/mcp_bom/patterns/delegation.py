from __future__ import annotations

import re

from mcp_bom._strip import language_for_path, strip_comments_and_strings
from mcp_bom.models import Confidence, DelegationResult

_PYTHON_PATTERNS = [
    r"\bmcp\.ClientSession\b",
    r"\bClientSession\b.*mcp",
    r"\bStdioServerParameters\b",
    r"\bSSEClientTransport\b",
    r"\bfrom\s+mcp\b.*import.*Client",
]

_TS_PATTERNS = [
    r"@modelcontextprotocol/sdk.*[Cc]lient",
    r"\bClient\b.*mcp",
    r"\bStdioClientTransport\b",
    r"\bSSEClientTransport\b",
    r"\bMCPClient\b",
]

_MCP_TRANSPORT_PATHS = [
    r"/sse",
    r"/mcp",
]

_MCP_METHODS = [
    r"tools/list",
    r"tools/call",
    r"resources/list",
    r"resources/read",
    r"prompts/list",
]

_DYNAMIC_INDICATORS = [
    r"\bdiscover\b",
    r"\bruntime\b",
    r"\bdynamic\b",
    r"\bon[_-]demand\b",
]


def detect(source_files: dict[str, str]) -> DelegationResult:
    result = DelegationResult(detected=False)
    evidence: list[str] = []
    has_delegation = False
    has_static = False
    has_dynamic = False
    delegate_count = 0

    masked_parts: list[str] = []

    for path, content in source_files.items():
        masked = strip_comments_and_strings(content, language_for_path(path))
        masked_parts.append(masked)
        patterns = _PYTHON_PATTERNS if path.endswith(".py") else _TS_PATTERNS if path.endswith((".ts", ".js")) else []

        for pat in patterns:
            if re.search(pat, masked, re.IGNORECASE):
                has_delegation = True
                has_static = True
                evidence.append(f"sdk:{pat}")
                delegate_count += 1

        for pat in _MCP_TRANSPORT_PATHS:
            matches = re.findall(pat, masked)
            if matches:
                has_delegation = True
                evidence.append(f"transport:{pat}")
                delegate_count += len(matches)

        for pat in _MCP_METHODS:
            if re.search(pat, masked):
                has_delegation = True
                evidence.append(f"method:{pat}")

    all_content = "\n".join(masked_parts)

    if has_delegation:
        for pat in _DYNAMIC_INDICATORS:
            if re.search(pat, all_content, re.IGNORECASE):
                has_dynamic = True
                break

        result.detected = True
        result.confidence = Confidence.HIGH if has_static else Confidence.MEDIUM
        result.static = has_static and not has_dynamic
        result.dynamic = has_dynamic
        result.count = delegate_count

    result.evidence = sorted(set(evidence))[:20]
    return result

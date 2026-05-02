from __future__ import annotations

import re

from mcp_bom.models import Confidence, EgressResult

_PYTHON_PATTERNS = [
    r"\brequests\.",
    r"\bhttpx\.",
    r"\burllib\.",
    r"\baiohttp\.",
    r"\bsocket\.connect\b",
    r"\bhttp\.client\b",
    r"\bpsycopg\b",
    r"\bpymongo\b",
    r"\bredis\b",
    r"\bmotor\b",
    r"\bmysql\b",
    r"\baiosqlite\b",
]

_TS_PATTERNS = [
    r"\bfetch\s*\(",
    r"\baxios\.",
    r"\bnode-fetch\b",
    r"\bhttp\.request\b",
    r"\bhttps\.request\b",
    r"\bgot\(",
    r"\bpg\b",
    r"\bmysql2\b",
    r"\bmongoose\b",
    r"\bprisma\b",
    r"\btypeorm\b",
    r"\bdrizzle\b",
    r"\bbetter-sqlite3\b",
    r"\bknex\b",
]

_GO_PATTERNS = [
    r"\bnet/http\b",
    r"\bnet\.Dial\b",
    r"\bhttp\.Get\b",
    r"\bhttp\.Post\b",
]

_ARBITRARY_HOST_INDICATORS = [
    r"\burl\b.*\bfetch\b",
    r"\bany\s+url\b",
    r"\barbitrary\b",
    r"\*\.onion",
    r"allow_any_host",
    r"noProxy",
    r"NO_PROXY",
]

_FIXED_DATASTORE_INDICATORS = [
    r"\bmongodb://",
    r"\bpostgres://",
    r"\bpostgresql://",
    r"\bredis://",
    r"\bmysql://",
    r"\belasticsearch",
]


def detect(source_files: dict[str, str]) -> EgressResult:
    result = EgressResult(detected=False)
    evidence: list[str] = []
    has_egress = False

    all_content = "\n".join(source_files.values())

    for path, content in source_files.items():
        patterns = []
        if path.endswith(".py"):
            patterns = _PYTHON_PATTERNS
        elif path.endswith((".ts", ".js", ".tsx", ".jsx")):
            patterns = _TS_PATTERNS
        elif path.endswith(".go"):
            patterns = _GO_PATTERNS

        for pat in patterns:
            found = re.findall(pat, content, re.IGNORECASE)
            if found:
                has_egress = True
                evidence.extend(found)

    if not has_egress:
        return result

    result.detected = True
    result.confidence = Confidence.HIGH

    is_arbitrary = False
    for pat in _ARBITRARY_HOST_INDICATORS:
        if re.search(pat, all_content, re.IGNORECASE):
            is_arbitrary = True
            break

    is_fixed_datastore = False
    for pat in _FIXED_DATASTORE_INDICATORS:
        if re.search(pat, all_content, re.IGNORECASE):
            is_fixed_datastore = True
            break

    result.arbitrary_host = is_arbitrary
    result.fixed_remote_datastore = is_fixed_datastore
    result.allowlisted_host = not is_arbitrary and not is_fixed_datastore

    protocols: list[str] = []
    if re.search(r"https?://", all_content):
        protocols.append("http")
    if re.search(r"wss?://", all_content):
        protocols.append("websocket")
    if re.search(r"redis://", all_content):
        protocols.append("redis")
    if re.search(r"(?:postgres|mongodb|mysql)://", all_content):
        protocols.append("datastore")
    result.protocols = list(set(protocols)) if protocols else ["http"]

    result.evidence = sorted(set(evidence))[:20]
    return result

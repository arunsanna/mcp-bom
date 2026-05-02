from __future__ import annotations

import re

from mcp_bom.models import Confidence, SecretsResult

_PYTHON_PATTERNS = {
    "config_env": [
        r"\bos\.environ\b",
        r"\bos\.getenv\b",
        r"\bdotenv\b",
        r"\bload_dotenv\b",
    ],
    "arbitrary_env": [
        r"\bos\.environ\.get\b",
        r"\bos\.environ\[",
    ],
    "keychain": [
        r"\bkeyring\b",
    ],
    "cloud_kms": [
        r"\bboto3\b.*secret",
        r"\bazure.*keyvault\b",
        r"\bgoogle.*secret.manager\b",
        r"\bSecretsManager\b",
    ],
}

_TS_PATTERNS = {
    "config_env": [
        r"\bprocess\.env\b",
        r"\bdotenv\b",
    ],
    "arbitrary_env": [
        r"\bprocess\.env\[",
    ],
    "cloud_kms": [
        r"\bAWS\.SecretsManager\b",
        r"\bSecretsManager\b",
    ],
}

_GO_PATTERNS = {
    "config_env": [
        r"\bos\.Getenv\b",
    ],
}


def detect(source_files: dict[str, str]) -> SecretsResult:
    result = SecretsResult(detected=False)
    evidence: list[str] = []
    detected_scopes: set[str] = set()
    has_read = False
    has_write = False

    for path, content in source_files.items():
        pattern_set: dict[str, list[str]] = {}
        if path.endswith(".py"):
            pattern_set = _PYTHON_PATTERNS
        elif path.endswith((".ts", ".js", ".tsx", ".jsx")):
            pattern_set = _TS_PATTERNS
        elif path.endswith(".go"):
            pattern_set = _GO_PATTERNS

        for scope_key, pats in pattern_set.items():
            for pat in pats:
                if re.search(pat, content, re.IGNORECASE):
                    has_read = True
                    detected_scopes.add(scope_key)
                    evidence.append(f"{scope_key}:{pat}")

        if re.search(r"\bos\.environ\[.*\]\s*=", content) or re.search(r"\bprocess\.env\[.*\]\s*=", content):
            has_write = True
            evidence.append("env_write")

    if has_read or has_write:
        result.detected = True
        result.confidence = Confidence.HIGH
        result.read = has_read
        result.write = has_write

        if "cloud_kms" in detected_scopes:
            result.scope = "cloud-kms"
        elif "keychain" in detected_scopes:
            result.scope = "system-keychain"
        elif "arbitrary_env" in detected_scopes:
            result.scope = "arbitrary-env"
        elif "config_env" in detected_scopes:
            result.scope = "process-env"
        else:
            result.scope = "unknown"

    result.evidence = sorted(set(evidence))[:20]
    return result

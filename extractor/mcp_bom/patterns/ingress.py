from __future__ import annotations

import re

from mcp_bom._strip import language_for_path, strip_comments_and_strings
from mcp_bom.models import Confidence, IngressResult

SCHEMA_PATTERNS: list[str] = []

_PYTHON_SERVER_PATTERNS = [
    (r"\bFlask\b", "python"),
    (r"\bFastAPI\b", "python"),
    (r"\buvicorn\b", "python"),
    (r"\bStarlette\b", "python"),
    (r"\baiohttp\.web\b", "python"),
]

_TS_SERVER_PATTERNS = [
    (r"\bexpress\b", "typescript"),
    (r"\bfastify\b", "typescript"),
    (r"\bhono\b", "typescript"),
    (r"\bKoa\b", "typescript"),
]

_BIND_0_0_0_0 = [
    r"0\.0\.0\.0",
    r"::",
    r"INADDR_ANY",
]

_BIND_LOCALHOST = [
    r"127\.0\.0\.1",
    r"localhost",
]

_AUTH_PATTERNS = [
    (r"\bBearer\b", "api-key"),
    (r"\bOAuth\b", "oauth"),
    (r"\bmTLS\b", "mtls"),
    (r"\bapi[_-]?key\b", "api-key"),
    (r"\bauthenticate\b", "api-key"),
    (r"\bauthMiddleware\b", "api-key"),
    (r"\bverifyToken\b", "api-key"),
]

_TLS_PATTERNS = [
    r"\bhttps\.createServer\b",
    r"\bTLS\b",
    r"\bssl\b",
    r"\bcert\b",
    r"\bkey\b.*\b.pem\b",
    r"\btls\.createServer\b",
]


def detect(source_files: dict[str, str], scope: str = "code") -> IngressResult:
    result = IngressResult(detected=False)
    evidence: list[str] = []
    has_server = False

    masked_parts: list[str] = []
    for path, content in source_files.items():
        masked_parts.append(strip_comments_and_strings(content, language_for_path(path)))
    all_content = "\n".join(masked_parts)

    all_server_patterns = _PYTHON_SERVER_PATTERNS + _TS_SERVER_PATTERNS
    for pat, _lang in all_server_patterns:
        if re.search(pat, all_content, re.IGNORECASE):
            has_server = True
            evidence.append(pat)

    # `.listen(` alone is too weak to be ingress evidence on its own — many
    # libraries expose `.listen(...)` for non-network event handlers. Only
    # count it if a known server framework was also imported.
    if has_server:
        listen_matches = re.findall(r"\.listen\s*\(", all_content)
        if listen_matches:
            evidence.append(".listen()")

    if not has_server:
        return result

    result.detected = True
    result.confidence = Confidence.HIGH

    bind_address = "localhost"
    for pat in _BIND_0_0_0_0:
        if re.search(pat, all_content):
            bind_address = "0.0.0.0"
            evidence.append(f"bind:{pat}")
            break
    if bind_address == "localhost":
        for pat in _BIND_LOCALHOST:
            if re.search(pat, all_content):
                evidence.append(f"bind:{pat}")
                break
    result.bind = bind_address

    auth = "none"
    for pat, auth_type in _AUTH_PATTERNS:
        if re.search(pat, all_content, re.IGNORECASE):
            auth = auth_type
            evidence.append(f"auth:{auth_type}")
            break
    result.auth = auth

    tls = False
    for pat in _TLS_PATTERNS:
        if re.search(pat, all_content, re.IGNORECASE):
            tls = True
            evidence.append(f"tls:{pat}")
            break
    result.tls_enabled = tls

    result.evidence = evidence[:20]
    return result

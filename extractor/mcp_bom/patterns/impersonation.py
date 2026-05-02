from __future__ import annotations

import re

from mcp_bom.models import Confidence, ImpersonationResult

_PYTHON_CHANNEL_PATTERNS = {
    "email": [r"\bsmtplib\b", r"\bimaplib\b", r"\bemail\.mime\b"],
    "calendar": [r"\bgoogleapiclient\b.*calendar", r"\bcaldav\b"],
    "chat": [r"\bslack_sdk\b", r"\bdiscord\.py\b", r"\bwebhooks?\b"],
    "social": [r"\btweepy\b", r"\btwitter\b"],
}

_TS_CHANNEL_PATTERNS = {
    "email": [r"\bnodemailer\b", r"\b@sendgrid\b"],
    "chat": [r"\b@slack/web-api\b", r"\bdiscord\.js\b", r"\b@discordjs\b"],
    "social": [r"\btwit\b", r"\btwitter-api\b"],
    "calendar": [r"\bgoogleapis\b.*calendar"],
}

_SCHEMA_WORDS = [
    r'"send_email"',
    r'"send_message"',
    r'"post"',
    r'"publish"',
    r'"tweet"',
    r'"send_slack"',
    r'"send"',
]

_NO_APPROVAL_INDICATORS = [
    r"\bauto[_-]?send\b",
    r"\bauto[_-]?post\b",
    r"\bno[_-]?confirm\b",
    r"\bskip[_-]?approval\b",
    r"\bautomated\b",
]


def detect(source_files: dict[str, str]) -> ImpersonationResult:
    result = ImpersonationResult(detected=False)
    evidence: list[str] = []
    channels: set[str] = set()
    approval_gate = True

    all_content = "\n".join(source_files.values())

    for path, content in source_files.items():
        channel_patterns = {}
        if path.endswith(".py"):
            channel_patterns = _PYTHON_CHANNEL_PATTERNS
        elif path.endswith((".ts", ".js", ".tsx", ".jsx")):
            channel_patterns = _TS_CHANNEL_PATTERNS

        for channel, pats in channel_patterns.items():
            for pat in pats:
                if re.search(pat, content, re.IGNORECASE):
                    channels.add(channel)
                    evidence.append(f"{channel}:{pat}")

        for pat in _SCHEMA_WORDS:
            found = re.findall(pat, content, re.IGNORECASE)
            if found:
                evidence.extend(found)

    for pat in _NO_APPROVAL_INDICATORS:
        if re.search(pat, all_content, re.IGNORECASE):
            approval_gate = False
            break

    if channels:
        result.detected = True
        result.confidence = Confidence.HIGH
        result.channels = sorted(channels)
        result.approval_gate = approval_gate
    elif evidence:
        result.detected = True
        result.confidence = Confidence.LOW

    result.evidence = sorted(set(evidence))[:20]
    return result

from __future__ import annotations

import re

from mcp_bom.models import Confidence, DataSensitivityResult

SCHEMA_PATTERNS = [
    r'"email"',
    r'"phone"',
    r'"address"',
    r'"ssn"',
    r'"credit_card"',
    r'"patient"',
]

_SENSITIVITY_PATTERNS = {
    "pii": [
        r"\bemail\b.*\baddress\b",
        r"\bphone\b",
        r"\bssn\b",
        r"\bsocial[_-]?security\b",
        r"\bdate[_-]?of[_-]?birth\b",
        r"\bpassport\b",
    ],
    "phi": [
        r"\bpatient\b",
        r"\bmedical\b",
        r"\bhealth[_-]?record\b",
        r"\bdiagnosis\b",
        r"\bHIPAA\b",
        r"\bphi\b",
    ],
    "financial": [
        r"\bcredit[_-]?card\b",
        r"\bbank[_-]?account\b",
        r"\bpayment\b",
        r"\btransaction\b",
        r"\binvoice\b",
    ],
    "location": [
        r"\bgps\b",
        r"\blocation\b.*\btrack\b",
        r"\blatitude\b",
        r"\blongitude\b",
        r"\bgeolocation\b",
    ],
}

_CRYPTO_INDICATORS = [
    r"\bcryptography\.fernet\b",
    r"\bhashlib\b",
    r"\bcrypto\b",
    r"\bbcrypt\b",
    r"\bencrypt\b",
    r"\bdecrypt\b",
]

_REDACTION_INDICATORS = [
    r"\bredact\b",
    r"\bmask\b",
    r"\banonymiz",
    r"\bscrub\b",
    r"\bstrip[_-]?pii\b",
]


def detect(source_files: dict[str, str], scope: str = "code") -> DataSensitivityResult:
    result = DataSensitivityResult(detected=False)
    evidence: list[str] = []
    detected_categories: set[str] = set()
    has_crypto = False
    has_redaction = False
    schema_hits = False

    all_content = "\n".join(source_files.values())

    for pat in SCHEMA_PATTERNS:
        if re.search(pat, all_content, re.IGNORECASE):
            schema_hits = True
            evidence.append(f"schema:{pat}")

    for path, content in source_files.items():
        for category, pats in _SENSITIVITY_PATTERNS.items():
            for pat in pats:
                if re.search(pat, content, re.IGNORECASE):
                    detected_categories.add(category)
                    evidence.append(f"{category}:{pat}")

        for pat in _CRYPTO_INDICATORS:
            if re.search(pat, content, re.IGNORECASE):
                has_crypto = True
                evidence.append(f"crypto:{pat}")

        for pat in _REDACTION_INDICATORS:
            if re.search(pat, content, re.IGNORECASE):
                has_redaction = True
                evidence.append(f"redact:{pat}")

    if detected_categories:
        result.detected = True
        result.confidence = Confidence.HIGH
        result.categories = sorted(detected_categories)
        result.redaction_declared = has_redaction
    elif has_crypto:
        result.detected = True
        result.confidence = Confidence.MEDIUM
        result.categories = []
        result.redaction_declared = has_redaction
    elif schema_hits:
        result.detected = True
        result.confidence = Confidence.LOW
        result.categories = []

    result.evidence = sorted(set(evidence))[:20]
    return result

"""Secrets capability detector with config-only vs secret disambiguation.

Per issue #17:
  - config-only: server reads an env var whose name is clearly infrastructure
                 config (PORT, HOST, NODE_ENV, LOG_LEVEL, etc.).  These are
                 innocuous and do NOT count toward the secrets capability.
  - secret: server reads an env var whose name matches secret patterns
            (API_KEY, TOKEN, SECRET, PASSWORD, AWS_SECRET_ACCESS_KEY, etc.).
            These DO count toward the secrets capability.
  - ambiguous: server reads an env var that matches neither set.  These count
               toward secrets with confidence=low.
  - Tier 2 (exposed): server reads the env *generically* (full dict, dynamic key,
                      subscript with non-literal). This is "secrets gateway"-shaped
                      and is weighted heavily by the score function.
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

# Env-var names that are clearly infrastructure configuration and should NOT
# count toward the secrets capability.  Case-insensitive match.
CONFIG_ONLY_PATTERNS = frozenset({
    # Networking / binding
    "PORT", "HOST", "HOSTNAME", "BIND", "ADDRESS",
    # Environment / stage
    "NODE_ENV", "ENV", "ENVIRONMENT", "STAGE", "TIER",
    # Logging / verbosity
    "DEBUG", "VERBOSE", "QUIET", "LOG_LEVEL", "LOG_FORMAT",
    # Locale / timezone
    "TZ", "TIMEZONE", "LOCALE", "LANG",
    # Shell / user identity (not secrets)
    "PWD", "HOME", "USER", "PATH",
    # Temp dirs
    "TEMP", "TMP", "TMPDIR",
    # Config / data paths
    "CONFIG_PATH", "CONFIG_FILE", "CONFIG_DIR",
    "DATA_PATH", "DATA_DIR", "WORK_DIR",
    # Operational tuning
    "TIMEOUT", "RETRY", "MAX_RETRIES", "INTERVAL",
    "WORKERS", "CONCURRENCY", "POOL_SIZE",
    # Protocol / version
    "PROTOCOL", "VERSION", "SCHEMA",
})

# Regex fragment matching env-var names that are clearly secrets.
_SECRET_INDICATORS_RE = re.compile(
    r"(?i)(API[_-]?KEY|TOKEN|SECRET|PASSWORD|PASSWD|"
    r"CREDENTIAL|AUTH[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|"
    r"BEARER|JWT|SESSION[_-]?KEY|ENCRYPTION[_-]?KEY|"
    r"AWS_(SECRET|ACCESS|SESSION)|GCP_|AZURE_|"
    r"DB_PASS|MYSQL_PASS|POSTGRES_PASS|MONGO_PASS|"
    r"SLACK_TOKEN|GITHUB_TOKEN|STRIPE_KEY|OPENAI_KEY|"
    r"ANTHROPIC_KEY|HF_TOKEN)"
)


def classify_env_read(name: str) -> str:
    """Classify an env-var name as 'config_only', 'secret', or 'ambiguous'.

    This is the public API consumed by the unit tests in
    tests/test_secrets_disambiguation.py.
    """
    upper = name.upper()
    if upper in CONFIG_ONLY_PATTERNS:
        return "config_only"
    if _SECRET_INDICATORS_RE.search(upper):
        return "secret"
    return "ambiguous"


def _ast_python(source: str, scope: str = "code") -> tuple[bool, bool, bool, bool, list[str]]:
    """Return (config_only, secret, tier2, write_seen, evidence)."""
    config_only = False
    secret = False
    tier2 = False
    write_seen = False
    evidence: list[str] = []

    tree, ranges, tool_text = python_tool_source(source)
    if tree is None:
        return config_only, secret, tier2, write_seen, evidence

    if scope == "tool" and not ranges:
        return config_only, secret, tier2, write_seen, evidence

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
                    classification = classify_env_read(arg0.value)
                    evidence.append(f"tier1:{mod or 'os'}.{attr}({arg0.value!r})[{classification}]")
                    if classification == "config_only":
                        config_only = True
                    elif classification == "secret":
                        secret = True
                    else:
                        secret = True  # ambiguous counts as secret
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
                    classification = classify_env_read(key.value)
                    evidence.append(f"tier1:os.environ[{key.value!r}][{classification}]")
                    if classification == "config_only":
                        config_only = True
                    elif classification == "secret":
                        secret = True
                    else:
                        secret = True
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

    return config_only, secret, tier2, write_seen, evidence



def _ts_js(masked: str, scope: str = "code") -> tuple[bool, bool, bool, bool, list[str]]:
    """Return (config_only, secret, tier2, write_seen, evidence)."""
    config_only = False
    secret = False
    tier2 = False
    write_seen = False
    evidence: list[str] = []

    lines = masked.splitlines()
    for i, line in enumerate(lines):
        if scope == "tool" and not near_tool_reg(lines, i, TS_TOOL_REG_PATS):
            continue
        # process.env.LITERAL — extract the name and classify it
        m = re.search(r"\bprocess\.env\.([A-Z_][A-Z0-9_]*)\b", line)
        if m:
            name = m.group(1)
            classification = classify_env_read(name)
            evidence.append(f"tier1:process.env.{name}[{classification}]")
            if classification == "config_only":
                config_only = True
            else:
                secret = True
        if re.search(r"\bprocess\.env\[", line):
            tier2 = True
            evidence.append("tier2:process.env[]")
        if re.search(r"\bprocess\.env\b(?!\s*\.\s*[A-Za-z_]|\s*\[)", line):
            tier2 = True
            evidence.append("tier2:process.env-bare")
        if re.search(r"\bprocess\.env\[[^\]]+\]\s*=", line):
            write_seen = True
            evidence.append("write:process.env[]=")

    return config_only, secret, tier2, write_seen, evidence


def _go(original: str, masked: str, scope: str = "code") -> tuple[bool, bool, bool, bool, list[str]]:
    """Return (config_only, secret, tier2, write_seen, evidence).

    Uses *original* (unmasked) content for extracting literal env-var names
    from os.Getenv("..."), because string-masking blanks them.  Uses *masked*
    content for all other patterns (os.Environ, os.Setenv, dynamic args).
    """
    config_only = False
    secret = False
    tier2 = False
    write_seen = False
    evidence: list[str] = []

    orig_lines = original.splitlines()
    masked_lines = masked.splitlines()

    for i, (orig_line, masked_line) in enumerate(zip(orig_lines, masked_lines)):
        if scope == "tool" and not near_tool_reg(masked_lines, i, GO_TOOL_REG_PATS):
            continue

        # os.Getenv("LITERAL") — use ORIGINAL line (string content is intact)
        m = re.search(r'\bos\.Getenv\s*\(\s*"([A-Za-z_][A-Za-z0-9_]*)"\s*\)', orig_line)
        if m:
            name = m.group(1)
            classification = classify_env_read(name)
            evidence.append(f"tier1:os.Getenv({name!r})[{classification}]")
            if classification == "config_only":
                config_only = True
            else:
                secret = True
        else:
            # os.Getenv(var) — dynamic key; check masked line to avoid
            # comment-only false positives
            if re.search(r"\bos\.Getenv\s*\(", masked_line):
                tier2 = True
                evidence.append("tier2:os.Getenv(var)")

        # Tier 2 / write patterns use masked lines
        if re.search(r"\bos\.Environ\s*\(\s*\)", masked_line):
            tier2 = True
            evidence.append("tier2:os.Environ()")
        if re.search(r"\bos\.Setenv\b", masked_line):
            write_seen = True
            evidence.append("write:os.Setenv")

    return config_only, secret, tier2, write_seen, evidence


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
    config_only_seen = False
    secret_seen = False
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
            co, sc, t2, w, ev = _ast_python(content, scope=scope)
        elif lang == "typescript":
            co, sc, t2, w, ev = _ts_js(masked, scope=scope)
        elif lang == "go":
            co, sc, t2, w, ev = _go(content, masked, scope=scope)
        else:
            continue

        config_only_seen = config_only_seen or co
        secret_seen = secret_seen or sc
        tier2_seen = tier2_seen or t2
        write_seen = write_seen or w
        evidence.extend(ev)

        kms_scope = _kms_or_keychain(masked, lang)
        if kms_scope and not kms_or_keychain_scope:
            kms_or_keychain_scope = kms_scope
            evidence.append(f"scope:{kms_scope}")

    # "active" means something beyond mere config-only reads
    active = secret_seen or tier2_seen or write_seen or kms_or_keychain_scope is not None

    if not (active or config_only_seen or schema_hits):
        return result

    # detected=True only if there's a real secret/exposed read, not just config
    result.detected = active

    if secret_seen or tier2_seen or write_seen or kms_or_keychain_scope:
        result.confidence = Confidence.HIGH
    elif config_only_seen and not active:
        result.confidence = Confidence.LOW
    elif schema_hits:
        result.confidence = Confidence.LOW

    result.read = active or config_only_seen
    result.write = write_seen

    if kms_or_keychain_scope == "cloud-kms":
        result.scope = "cloud-kms"
    elif kms_or_keychain_scope == "system-keychain":
        result.scope = "system-keychain"
    elif tier2_seen:
        result.scope = "arbitrary-env"
    elif secret_seen:
        result.scope = "process-env"
    elif write_seen:
        result.scope = "process-env"
    elif config_only_seen and not active:
        result.scope = "config-only"
    elif schema_hits:
        result.scope = "schema-only"
    else:
        result.scope = "unknown"

    result.evidence = sorted(set(evidence))[:20]
    return result

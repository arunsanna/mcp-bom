"""Tests for the config-only vs secret env-read classifier (issue #17)."""

from __future__ import annotations

import pytest

from mcp_bom.patterns.secrets import classify_env_read


@pytest.mark.parametrize("name,expected", [
    # Config-only patterns
    ("PORT", "config_only"),
    ("port", "config_only"),
    ("HOST", "config_only"),
    ("HOSTNAME", "config_only"),
    ("BIND", "config_only"),
    ("ADDRESS", "config_only"),
    ("NODE_ENV", "config_only"),
    ("ENV", "config_only"),
    ("ENVIRONMENT", "config_only"),
    ("DEBUG", "config_only"),
    ("VERBOSE", "config_only"),
    ("LOG_LEVEL", "config_only"),
    ("TZ", "config_only"),
    ("HOME", "config_only"),
    ("USER", "config_only"),
    ("PATH", "config_only"),
    ("TEMP", "config_only"),
    ("TMP", "config_only"),
    ("CONFIG_PATH", "config_only"),
    ("DATA_DIR", "config_only"),
    ("TIMEOUT", "config_only"),
    ("WORKERS", "config_only"),
    ("VERSION", "config_only"),
    # Secret patterns
    ("AWS_SECRET_ACCESS_KEY", "secret"),
    ("OPENAI_API_KEY", "secret"),
    ("STRIPE_SECRET_KEY", "secret"),
    ("DB_PASSWORD", "secret"),
    ("GITHUB_TOKEN", "secret"),
    ("API_KEY", "secret"),
    ("TOKEN", "secret"),
    ("SECRET", "secret"),
    ("PASSWORD", "secret"),
    ("PASSWD", "secret"),
    ("CREDENTIAL", "secret"),
    ("AUTH_KEY", "secret"),
    ("ACCESS_KEY", "secret"),
    ("PRIVATE_KEY", "secret"),
    ("BEARER", "secret"),
    ("JWT", "secret"),
    ("SESSION_KEY", "secret"),
    ("ENCRYPTION_KEY", "secret"),
    ("AWS_SECRET", "secret"),
    ("AWS_ACCESS_KEY_ID", "secret"),
    ("AWS_SESSION_TOKEN", "secret"),
    ("GCP_SERVICE_ACCOUNT", "secret"),
    ("AZURE_CLIENT_SECRET", "secret"),
    ("DB_PASS", "secret"),
    ("MYSQL_PASS", "secret"),
    ("POSTGRES_PASS", "secret"),
    ("MONGO_PASS", "secret"),
    ("SLACK_TOKEN", "secret"),
    ("STRIPE_KEY", "secret"),
    ("OPENAI_KEY", "secret"),
    ("ANTHROPIC_KEY", "secret"),
    ("HF_TOKEN", "secret"),
    # Ambiguous — not clearly config, not clearly secret
    ("WEIRD_NAME", "ambiguous"),
    ("DATABASE_URL", "ambiguous"),
    ("REDIS_URL", "ambiguous"),
    ("SOME_CUSTOM_VAR", "ambiguous"),
    ("MY_APP_SETTING", "ambiguous"),
])
def test_classify_env_read(name, expected):
    assert classify_env_read(name) == expected, f"classify_env_read({name!r}) returned {classify_env_read(name)!r}, expected {expected!r}"

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_bom.extractor import extract
from mcp_bom.models import Confidence
from mcp_bom.scorer import score_vector, load_weights

FIXTURES = Path(__file__).parent / "fixtures"
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCORE_TOML = REPO_ROOT / "score_function.toml"


class TestFilesystemDetector:
    def test_detects_read_write_delete_in_dangerous_server(self):
        report = extract(FIXTURES / "dangerous_server")
        fs = report.capability_vector.filesystem
        assert fs.detected is True
        assert fs.read is True
        assert fs.write is True
        assert fs.delete is True
        assert fs.confidence in (Confidence.HIGH, Confidence.MEDIUM)

    def test_safe_server_has_low_or_no_filesystem(self):
        report = extract(FIXTURES / "safe_server")
        fs = report.capability_vector.filesystem
        assert fs.read is True
        assert fs.write is False
        assert fs.delete is False


class TestShellDetector:
    def test_detects_subprocess_in_python(self):
        report = extract(FIXTURES / "dangerous_server")
        sh = report.capability_vector.shell
        assert sh.detected is True
        assert sh.direct is True
        assert sh.code_evaluation_vector == "unsafe_deserialization"

    def test_detects_child_process_in_typescript(self):
        report = extract(FIXTURES / "ts_shell_server")
        sh = report.capability_vector.shell
        assert sh.detected is True
        assert sh.direct is True


class TestEgressDetector:
    def test_detects_requests_and_httpx(self):
        report = extract(FIXTURES / "dangerous_server")
        eg = report.capability_vector.egress
        assert eg.detected is True
        assert "http" in eg.protocols

    def test_detects_go_net_http(self):
        report = extract(FIXTURES / "go_egress_server")
        eg = report.capability_vector.egress
        assert eg.detected is True


class TestSecretsDetector:
    def test_detects_os_environ(self):
        report = extract(FIXTURES / "dangerous_server")
        se = report.capability_vector.secrets
        assert se.detected is True
        assert se.read is True

    def test_tier1_literal_env_classified_as_process_env(self):
        report = extract(FIXTURES / "tier1_secrets_server")
        se = report.capability_vector.secrets
        assert se.detected is True
        assert se.scope == "process-env"  # Tier 1 — config-only

    def test_tier2_dynamic_env_classified_as_arbitrary(self):
        report = extract(FIXTURES / "tier2_secrets_server")
        se = report.capability_vector.secrets
        assert se.detected is True
        assert se.scope == "arbitrary-env"  # Tier 2 — exposed


class TestFalsePositiveReductions:
    def test_client_in_comments_does_not_trigger_delegation(self):
        report = extract(FIXTURES / "comment_only_delegation")
        de = report.capability_vector.delegation
        assert de.detected is False, f"FP: {de.evidence}"


class TestScorer:
    def test_score_is_deterministic(self):
        report1 = extract(FIXTURES / "dangerous_server")
        report2 = extract(FIXTURES / "dangerous_server")
        assert report1.score.attack_surface_score == report2.score.attack_surface_score

    def test_dangerous_server_scores_high(self):
        report = extract(FIXTURES / "dangerous_server")
        assert report.score.attack_surface_score > 30

    def test_safe_server_scores_low(self):
        report = extract(FIXTURES / "safe_server")
        assert report.score.attack_surface_score < 50

    def test_score_range_0_to_100(self):
        for fixture in ["dangerous_server", "safe_server", "ts_shell_server", "go_egress_server"]:
            report = extract(FIXTURES / fixture)
            assert 0 <= report.score.attack_surface_score <= 100, f"{fixture}: {report.score.attack_surface_score}"

    def test_weights_load_from_toml(self):
        config = load_weights(SCORE_TOML)
        assert config["weights"]["depth"] == 0.45
        assert config["version"] == "1.0"
        assert config["status"] == "locked-v1"

    def test_breadth_reflects_detected_categories(self):
        report = extract(FIXTURES / "dangerous_server")
        cats = report.capability_vector.categories()
        detected = sum(1 for c in cats.values() if c.detected)
        expected = (detected / 8) * 100
        assert abs(report.score.breadth - expected) < 0.1


class TestReportSerialization:
    def test_report_serializes_to_valid_json(self):
        report = extract(FIXTURES / "dangerous_server")
        data = report.model_dump(mode="json")
        text = json.dumps(data)
        parsed = json.loads(text)
        assert "server_id" in parsed
        assert "capability_vector" in parsed
        assert "score" in parsed
        assert "attack_surface_score" in parsed["score"]


class TestLanguageDetection:
    def test_detects_python(self):
        report = extract(FIXTURES / "dangerous_server")
        from mcp_bom.models import Language
        assert Language.PYTHON in report.languages_detected

    def test_detects_typescript(self):
        report = extract(FIXTURES / "ts_shell_server")
        from mcp_bom.models import Language
        assert Language.TYPESCRIPT in report.languages_detected

    def test_detects_go(self):
        report = extract(FIXTURES / "go_egress_server")
        from mcp_bom.models import Language
        assert Language.GO in report.languages_detected

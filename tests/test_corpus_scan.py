from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys_path_injected = False

if not sys_path_injected:
    import sys
    sys.path.insert(0, str(REPO_ROOT / "extractor"))
    sys_path_injected = True

from run_corpus_scan import (
    resolve_download_url,
    _source_tier,
    compute_labeled_ids,
    prefilter,
    _pct,
)

MANIFEST = REPO_ROOT / "corpus" / "manifest.json"


@pytest.fixture(scope="module")
def servers():
    return json.loads(MANIFEST.read_text())["servers"]


class TestSourceTier:
    def test_official_registry(self, servers):
        for s in servers:
            if s.get("registry") == "official":
                assert _source_tier(s) == "official"
                break

    def test_community_default(self, servers):
        community = [s for s in servers if s.get("registry") == "github" and "anthropic" not in (s.get("repo_url", "") or "").lower()]
        if community:
            assert _source_tier(community[0]) == "community"

    def test_enterprise_repo(self):
        server = {"registry": "github", "repo_url": "https://github.com/anthropic/some-server", "maintainer": "someone"}
        assert _source_tier(server) == "enterprise"


class TestUrlResolution:
    def test_github_resolves(self, servers):
        gh = [s for s in servers if s.get("repo_url", "").startswith("https://github.com")]
        if gh:
            url = resolve_download_url(gh[0])
            assert url is not None
            assert "github" in url

    def test_remote_without_repo_returns_none(self, servers):
        remote_no_repo = [s for s in servers if s.get("language") == "remote" and not s.get("repo_url")]
        if remote_no_repo:
            assert resolve_download_url(remote_no_repo[0]) is None


class TestLabeledSubset:
    def test_deterministic(self, servers):
        ids1 = compute_labeled_ids(servers)
        ids2 = compute_labeled_ids(servers)
        assert ids1 == ids2

    def test_correct_size(self, servers):
        ids = compute_labeled_ids(servers)
        assert len(ids) == 50

    def test_all_ids_valid(self, servers):
        all_ids = {s["id"] for s in servers}
        ids = compute_labeled_ids(servers)
        assert ids.issubset(all_ids)


class TestPercentile:
    def test_p50(self):
        assert _pct([1, 2, 3, 4, 5], 50) == 3

    def test_empty(self):
        assert _pct([], 50) == 0.0

    def test_single(self):
        assert _pct([42], 50) == 42


class TestPrefilter:
    def test_remote_excluded(self, servers, tmp_path):
        scannable, n_remote, n_no_source = prefilter(servers, tmp_path / "scored")
        assert n_remote == 181
        remote_ids = {s["id"] for s in servers if s.get("language") == "remote"}
        for s in scannable:
            assert s["id"] not in remote_ids

    def test_scannable_set_written(self, servers, tmp_path):
        output = tmp_path / "scored"
        val_dir = tmp_path / "validation"
        prefilter(servers, output, val_dir=val_dir)
        path = val_dir / "scannable_set.json"
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["total"] > 0
        assert len(data["ids"]) == data["total"]

    def test_idempotent(self, servers, tmp_path):
        output = tmp_path / "scored"
        val_dir = tmp_path / "validation"
        s1, r1, n1 = prefilter(servers, output, val_dir=val_dir)
        s2, r2, n2 = prefilter(servers, output, val_dir=val_dir)
        assert len(s1) == len(s2)
        assert r1 == r2
        assert n1 == n2

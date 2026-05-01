import json
import tempfile
import unittest
from pathlib import Path

from corpus.build_manifest import (
    ManifestBuilder,
    ManifestRecord,
    build_manifest_document,
    merge_records,
    select_stratified,
    stable_id,
)


class ManifestBuilderTests(unittest.TestCase):
    def test_stable_id_keeps_registry_namespace_readable(self):
        self.assertEqual(
            stable_id("npm", "@modelcontextprotocol/server-filesystem"),
            "npm-modelcontextprotocol-server-filesystem",
        )

    def test_merge_records_combines_sources_and_preserves_best_metadata(self):
        records = [
            ManifestRecord(
                id="",
                name="Example MCP",
                registry="github",
                repo_url="https://github.com/Example/MCP",
                version="",
                language="python",
                install_count=10,
                last_update="2026-04-01",
                source_archive_path=None,
                license="MIT",
                maintainer="example",
                signed=False,
                description="from github",
                sources=["github"],
            ),
            ManifestRecord(
                id="",
                name="example-mcp",
                registry="smithery",
                repo_url="https://github.com/example/mcp",
                version="1.2.3",
                language="",
                install_count=42,
                last_update="2026-04-02",
                source_archive_path=None,
                license="",
                maintainer="",
                signed=False,
                description="from smithery",
                sources=["smithery"],
            ),
        ]

        merged = merge_records(records)

        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].version, "1.2.3")
        self.assertEqual(merged[0].language, "python")
        self.assertEqual(merged[0].install_count, 42)
        self.assertEqual(merged[0].last_update, "2026-04-02")
        self.assertEqual(merged[0].sources, ["github", "smithery"])

    def test_select_stratified_keeps_source_coverage_and_target_size(self):
        records = []
        for source in ["npm", "pypi", "github", "official", "smithery"]:
            for idx in range(5):
                records.append(
                    ManifestRecord(
                        id=f"{source}-{idx}",
                        name=f"{source}-{idx}",
                        registry=source,
                        repo_url="",
                        version="",
                        language="unknown",
                        install_count=idx,
                        last_update="",
                        source_archive_path=None,
                        license="",
                        maintainer="",
                        signed=False,
                        description="",
                        sources=[source],
                    )
                )

        selected = select_stratified(records, target=10)
        sources = {record.registry for record in selected}

        self.assertEqual(len(selected), 10)
        self.assertEqual(sources, {"npm", "pypi", "github", "official", "smithery"})

    def test_build_manifest_document_has_required_metadata_and_fields(self):
        records = [
            ManifestRecord(
                id="npm-example",
                name="example",
                registry="npm",
                repo_url="https://github.com/example/example",
                version="1.0.0",
                language="typescript",
                install_count=100,
                last_update="2026-04-01",
                source_archive_path="raw/npm-example.tgz",
                license="MIT",
                maintainer="maintainer",
                signed=False,
                description="Example server",
                sources=["npm"],
            )
        ]

        document = build_manifest_document(records, snapshot_date="2026-05-01")

        self.assertEqual(document["snapshot_date"], "2026-05-01")
        self.assertEqual(document["server_count"], 1)
        self.assertEqual(document["source_counts"], {"npm": 1})
        self.assertEqual(document["servers"][0]["source_archive_path"], "raw/npm-example.tgz")

    def test_builder_writes_manifest_and_archive_metadata_for_catalog_only_entries(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            builder = ManifestBuilder(repo_root=root, snapshot_date="2026-05-01")
            record = ManifestRecord(
                id="official-remote",
                name="remote-only",
                registry="official",
                repo_url="",
                version="1.0.0",
                language="remote",
                install_count=0,
                last_update="2026-04-01",
                source_archive_path=None,
                license="",
                maintainer="",
                signed=False,
                description="Remote-only server",
                sources=["official"],
            )

            manifest_path = builder.write_manifest([record])
            archive_path = root / "corpus" / "raw" / "official-remote.metadata.json"

            self.assertTrue(manifest_path.exists())
            self.assertTrue(archive_path.exists())
            manifest = json.loads(manifest_path.read_text())
            self.assertEqual(manifest["servers"][0]["source_archive_path"], "raw/official-remote.metadata.json")


if __name__ == "__main__":
    unittest.main()

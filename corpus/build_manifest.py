#!/usr/bin/env python3
"""Build the MCP-BOM corpus manifest from public registry sources."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


OFFICIAL_REGISTRY_URL = "https://registry.modelcontextprotocol.io/v0/servers"
SMITHERY_SERVERS_URL = "https://api.smithery.ai/servers"
NPM_SEARCH_URL = "https://registry.npmjs.org/-/v1/search"
NPM_PACKAGE_URL = "https://registry.npmjs.org/{name}"
PYPI_PACKAGE_URL = "https://pypi.org/pypi/{name}/json"

DEFAULT_NPM_QUERIES = [
    "@modelcontextprotocol",
    "mcp-server",
    "model context protocol server",
    "mcp server",
    "fastmcp",
]

DEFAULT_GITHUB_QUERIES = [
    "topic:mcp-server",
    "mcp-server",
    "\"model context protocol\" server",
    "fastmcp server",
    "mcp server language:python",
    "mcp server language:typescript",
    "mcp server language:go",
]

KNOWN_PYPI_PACKAGES = [
    "mcp",
    "fastmcp",
    "mcp-server-fetch",
    "mcp-server-git",
    "mcp-server-time",
    "mcp-server-sqlite",
    "mcp-server-postgres",
    "mcp-server-sentry",
    "mcp-server-docker",
    "mcp-shell-server",
    "mcp-server-mysql",
    "mcp-server-redis",
    "mcp-server-filesystem",
    "mcp-server-github",
    "mcp-server-slack",
    "mcp-server-brave-search",
    "mcp-server-gdrive",
    "mcp-server-memory",
    "mcp-server-puppeteer",
    "mcp-server-everything",
    "mcp-server-sequential-thinking",
    "mcp-server-aws-kb-retrieval",
    "mcp-server-langchain",
    "mcp-server-qdrant",
    "mcp-server-raygun",
    "mcp-server-airtable",
    "mcp-server-bigquery",
    "mcp-server-snowflake",
    "mcp-server-notion",
    "mcp-server-linear",
    "mcp-server-jira",
    "mcp-server-confluence",
    "mcp-server-stripe",
    "agentictrade-mcp",
    "auto-mcp-tool",
    "gobox-mcp",
]


@dataclass
class ManifestRecord:
    id: str
    name: str
    registry: str
    repo_url: str
    version: str
    language: str
    install_count: int
    last_update: str
    source_archive_path: str | None
    license: str
    maintainer: str
    signed: bool
    description: str
    sources: list[str] = field(default_factory=list)
    package_url: str = ""
    homepage_url: str = ""
    source_archive_url: str = ""

    def manifest_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("source_archive_url", None)
        return data


def stable_id(registry: str, name: str) -> str:
    raw = f"{registry}-{name}".lower()
    raw = raw.replace("@", "")
    raw = re.sub(r"[^a-z0-9]+", "-", raw)
    raw = re.sub(r"-+", "-", raw).strip("-")
    return raw or "unknown-server"


def normalize_language(value: str | None) -> str:
    language = (value or "").strip().lower()
    if language in {"ts", "typescript", "javascript", "js"}:
        return "typescript"
    if language in {"python", "py"}:
        return "python"
    if language in {"golang", "go"}:
        return "go"
    return language or "unknown"


def normalize_repo_url(url: str | None) -> str:
    if not url:
        return ""
    url = str(url).strip()
    if url.startswith("git+"):
        url = url[4:]
    if url.startswith("git@github.com:"):
        url = "https://github.com/" + url.removeprefix("git@github.com:")
    url = url.removesuffix(".git")
    parsed = urllib.parse.urlparse(url)
    if parsed.netloc.lower() == "github.com":
        parts = [part for part in parsed.path.strip("/").split("/") if part]
        if len(parts) >= 2:
            return f"https://github.com/{parts[0]}/{parts[1]}"
    return url


def github_archive_url(repo_url: str) -> str:
    parsed = urllib.parse.urlparse(normalize_repo_url(repo_url))
    if parsed.netloc.lower() != "github.com":
        return ""
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) < 2:
        return ""
    return f"https://api.github.com/repos/{parts[0]}/{parts[1]}/zipball"


def dedupe_key(record: ManifestRecord) -> str:
    repo_url = normalize_repo_url(record.repo_url).lower()
    if repo_url and "github.com/" in repo_url:
        return f"github:{repo_url}"
    package_name = record.name.lower().strip()
    return f"{record.registry}:{package_name}"


def merge_records(records: list[ManifestRecord]) -> list[ManifestRecord]:
    merged: dict[str, ManifestRecord] = {}
    for record in records:
        record.repo_url = normalize_repo_url(record.repo_url)
        record.language = normalize_language(record.language)
        record.sources = sorted(set(record.sources or [record.registry]))
        key = dedupe_key(record)
        if key not in merged:
            record.id = record.id or stable_id(record.registry, record.name)
            merged[key] = record
            continue

        existing = merged[key]
        existing.sources = sorted(set(existing.sources + record.sources + [record.registry]))
        existing.install_count = max(existing.install_count, record.install_count)
        if record.last_update > existing.last_update:
            existing.last_update = record.last_update
        for attr in [
            "version",
            "language",
            "repo_url",
            "source_archive_path",
            "license",
            "maintainer",
            "description",
            "package_url",
            "homepage_url",
            "source_archive_url",
        ]:
            current = getattr(existing, attr)
            incoming = getattr(record, attr)
            if not current or current == "unknown":
                setattr(existing, attr, incoming)
        existing.signed = existing.signed or record.signed

    return sorted(
        merged.values(),
        key=lambda item: (-item.install_count, item.registry, item.name.lower()),
    )


def select_stratified(records: list[ManifestRecord], target: int) -> list[ManifestRecord]:
    if len(records) <= target:
        return sorted(records, key=lambda item: (-item.install_count, item.registry, item.name.lower()))

    buckets: dict[str, list[ManifestRecord]] = {}
    for record in records:
        buckets.setdefault(record.registry, []).append(record)
    for bucket in buckets.values():
        bucket.sort(key=lambda item: (-item.install_count, item.name.lower()))

    quota = max(1, target // max(1, len(buckets)))
    selected: list[ManifestRecord] = []
    selected_ids: set[str] = set()
    for source in sorted(buckets):
        for record in buckets[source][:quota]:
            if record.id not in selected_ids:
                selected.append(record)
                selected_ids.add(record.id)

    remaining = [
        record
        for record in sorted(records, key=lambda item: (-item.install_count, item.registry, item.name.lower()))
        if record.id not in selected_ids
    ]
    selected.extend(remaining[: max(0, target - len(selected))])
    return selected[:target]


def build_manifest_document(records: list[ManifestRecord], snapshot_date: str) -> dict[str, Any]:
    source_counts: dict[str, int] = {}
    language_counts: dict[str, int] = {}
    for record in records:
        source_counts[record.registry] = source_counts.get(record.registry, 0) + 1
        language_counts[record.language] = language_counts.get(record.language, 0) + 1
    return {
        "schema_version": "mcp-bom-corpus-manifest-v1",
        "snapshot_date": snapshot_date,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "server_count": len(records),
        "source_counts": dict(sorted(source_counts.items())),
        "language_counts": dict(sorted(language_counts.items())),
        "servers": [record.manifest_dict() for record in records],
    }


def fetch_json(url: str, *, timeout: int = 30, headers: dict[str, str] | None = None) -> Any:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "mcp-bom-corpus-builder/1.0",
            **(headers or {}),
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def parse_npm_repository(value: Any) -> str:
    if isinstance(value, dict):
        return value.get("url", "") or value.get("directory", "")
    if isinstance(value, str):
        return value
    return ""


def latest_npm_tarball(package_metadata: dict[str, Any], version: str) -> str:
    versions = package_metadata.get("versions", {})
    selected = versions.get(version) or versions.get(package_metadata.get("dist-tags", {}).get("latest", ""))
    if not isinstance(selected, dict):
        return ""
    return selected.get("dist", {}).get("tarball", "")


def fetch_official_registry(limit: int = 700) -> list[ManifestRecord]:
    records: list[ManifestRecord] = []
    cursor = ""
    seen_cursors: set[str] = set()
    while len(records) < limit:
        params = {"limit": "100"}
        if cursor:
            params["cursor"] = cursor
        url = f"{OFFICIAL_REGISTRY_URL}?{urllib.parse.urlencode(params)}"
        data = fetch_json(url)
        for item in data.get("servers", []):
            server = item.get("server", {})
            meta = item.get("_meta", {}).get("io.modelcontextprotocol.registry/official", {})
            if meta.get("isLatest") is False:
                continue
            name = server.get("name", "")
            if not name:
                continue
            repo = normalize_repo_url(server.get("repository", {}).get("url", ""))
            homepage = server.get("websiteUrl", "") or server.get("homepage", "")
            packages = server.get("packages", []) or []
            language = "remote" if server.get("remotes") else "unknown"
            package_url = ""
            archive_url = github_archive_url(repo)
            if packages and isinstance(packages[0], dict):
                package_info = packages[0]
                package_url = package_info.get("identifier", "")
                if package_info.get("registryType") == "npm":
                    language = "typescript"
                elif package_info.get("registryType") == "pypi":
                    language = "python"
            records.append(
                ManifestRecord(
                    id="",
                    name=name,
                    registry="official",
                    repo_url=repo,
                    version=server.get("version", ""),
                    language=language,
                    install_count=0,
                    last_update=meta.get("updatedAt", "") or meta.get("publishedAt", ""),
                    source_archive_path=None,
                    license=server.get("license", ""),
                    maintainer=server.get("publisher", {}).get("name", ""),
                    signed=False,
                    description=(server.get("description", "") or "")[:500],
                    sources=["official"],
                    package_url=package_url,
                    homepage_url=homepage,
                    source_archive_url=archive_url,
                )
            )
        metadata = data.get("metadata", {})
        next_cursor = metadata.get("nextCursor", "")
        if not next_cursor or next_cursor in seen_cursors:
            break
        seen_cursors.add(next_cursor)
        cursor = next_cursor
    return records


def fetch_smithery(limit: int = 700) -> list[ManifestRecord]:
    records: list[ManifestRecord] = []
    page = 1
    page_size = 100
    while len(records) < limit:
        params = {"page": str(page), "pageSize": str(page_size), "topK": "500"}
        url = f"{SMITHERY_SERVERS_URL}?{urllib.parse.urlencode(params)}"
        try:
            data = fetch_json(url)
        except (urllib.error.HTTPError, urllib.error.URLError):
            break
        servers = data.get("servers", [])
        if not servers:
            break
        for server in servers:
            name = server.get("qualifiedName") or server.get("displayName") or server.get("id")
            if not name:
                continue
            homepage = server.get("homepage", "") or ""
            repo = normalize_repo_url(homepage if "github.com/" in homepage else "")
            records.append(
                ManifestRecord(
                    id="",
                    name=name,
                    registry="smithery",
                    repo_url=repo,
                    version="",
                    language="remote" if server.get("remote") else "unknown",
                    install_count=int(server.get("useCount") or 0),
                    last_update=server.get("createdAt", ""),
                    source_archive_path=None,
                    license="",
                    maintainer=server.get("namespace", "") or server.get("owner", ""),
                    signed=bool(server.get("verified")),
                    description=(server.get("description", "") or "")[:500],
                    sources=["smithery"],
                    package_url=f"https://smithery.ai/server/{name}",
                    homepage_url=homepage,
                    source_archive_url=github_archive_url(repo),
                )
            )
        pagination = data.get("pagination", {})
        if page >= int(pagination.get("totalPages", page)):
            break
        page += 1
    return records[:limit]


def fetch_npm(limit: int = 300) -> list[ManifestRecord]:
    records: list[ManifestRecord] = []
    seen: set[str] = set()
    for query in DEFAULT_NPM_QUERIES:
        params = {"text": query, "size": "100"}
        data = fetch_json(f"{NPM_SEARCH_URL}?{urllib.parse.urlencode(params)}")
        for item in data.get("objects", []):
            package = item.get("package", {})
            name = package.get("name", "")
            if not name or name in seen:
                continue
            desc = (package.get("description", "") or "").lower()
            if "mcp" not in name.lower() and "model context protocol" not in desc and "mcp" not in desc:
                continue
            seen.add(name)
            version = package.get("version", "")
            repo = normalize_repo_url(package.get("links", {}).get("repository", ""))
            archive_url = ""
            license_name = ""
            last_update = package.get("date", "")
            maintainer = package.get("publisher", {}).get("username", "")
            try:
                package_data = fetch_json(NPM_PACKAGE_URL.format(name=urllib.parse.quote(name, safe="@/")), timeout=20)
                latest_version = package_data.get("dist-tags", {}).get("latest", version)
                version = latest_version or version
                latest_data = package_data.get("versions", {}).get(version, {})
                repo = normalize_repo_url(parse_npm_repository(latest_data.get("repository")) or repo)
                archive_url = latest_npm_tarball(package_data, version)
                license_name = latest_data.get("license", "") or package_data.get("license", "")
                last_update = package_data.get("time", {}).get(version, last_update)
                maintainers = package_data.get("maintainers", [])
                if maintainers and isinstance(maintainers[0], dict):
                    maintainer = maintainers[0].get("name", maintainer)
            except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError):
                pass
            records.append(
                ManifestRecord(
                    id="",
                    name=name,
                    registry="npm",
                    repo_url=repo,
                    version=version,
                    language="typescript",
                    install_count=int(item.get("score", {}).get("detail", {}).get("popularity", 0) * 1_000_000),
                    last_update=last_update,
                    source_archive_path=None,
                    license=license_name,
                    maintainer=maintainer,
                    signed=False,
                    description=(package.get("description", "") or "")[:500],
                    sources=["npm"],
                    package_url=f"https://www.npmjs.com/package/{name}",
                    homepage_url=package.get("links", {}).get("homepage", ""),
                    source_archive_url=archive_url or github_archive_url(repo),
                )
            )
            if len(records) >= limit:
                return records
            time.sleep(0.05)
    return records


def fetch_pypi(limit: int = 100) -> list[ManifestRecord]:
    records: list[ManifestRecord] = []
    for name in KNOWN_PYPI_PACKAGES:
        try:
            data = fetch_json(PYPI_PACKAGE_URL.format(name=urllib.parse.quote(name)), timeout=20)
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError):
            continue
        info = data.get("info", {})
        version = info.get("version", "")
        project_urls = info.get("project_urls") or {}
        repo = normalize_repo_url(
            project_urls.get("Repository", "")
            or project_urls.get("Source", "")
            or info.get("home_page", "")
        )
        archive_url = ""
        releases = data.get("releases", {}).get(version, [])
        for release in releases:
            if release.get("packagetype") == "sdist":
                archive_url = release.get("url", "")
                break
        if not archive_url and releases:
            archive_url = releases[0].get("url", "")
        last_update = max((release.get("upload_time_iso_8601", "") for release in releases), default="")
        records.append(
            ManifestRecord(
                id="",
                name=name,
                registry="pypi",
                repo_url=repo,
                version=version,
                language="python",
                install_count=0,
                last_update=last_update,
                source_archive_path=None,
                license=info.get("license", "") or "",
                maintainer=info.get("maintainer", "") or info.get("author", "") or "",
                signed=False,
                description=(info.get("summary", "") or "")[:500],
                sources=["pypi"],
                package_url=info.get("package_url", f"https://pypi.org/project/{name}/"),
                homepage_url=info.get("home_page", ""),
                source_archive_url=archive_url or github_archive_url(repo),
            )
        )
        if len(records) >= limit:
            break
        time.sleep(0.05)
    return records


def gh_search(query: str, limit: int) -> list[dict[str, Any]]:
    base_cmd = [
        "gh",
        "search",
        "repos",
        query,
        "--limit",
        str(limit),
        "--json",
        "name,url,description,language,stargazersCount,updatedAt,owner,licenseInfo",
    ]
    result = subprocess.run(base_cmd, capture_output=True, text=True, timeout=90, check=False)
    if result.returncode != 0 and "licenseInfo" in base_cmd[-1]:
        base_cmd[-1] = "name,url,description,language,stargazersCount,updatedAt,owner"
        result = subprocess.run(base_cmd, capture_output=True, text=True, timeout=90, check=False)
    if result.returncode != 0:
        return []
    return json.loads(result.stdout or "[]")


def fetch_github(limit: int = 700) -> list[ManifestRecord]:
    records: list[ManifestRecord] = []
    seen: set[str] = set()
    per_query = max(100, min(300, limit))
    for query in DEFAULT_GITHUB_QUERIES:
        for repo in gh_search(query, per_query):
            repo_url = normalize_repo_url(repo.get("url", ""))
            if not repo_url or repo_url in seen:
                continue
            seen.add(repo_url)
            owner = repo.get("owner", {}).get("login", "")
            license_info = repo.get("licenseInfo") or {}
            records.append(
                ManifestRecord(
                    id="",
                    name=repo.get("name", ""),
                    registry="github",
                    repo_url=repo_url,
                    version="",
                    language=normalize_language(repo.get("language", "")),
                    install_count=int(repo.get("stargazersCount") or 0),
                    last_update=repo.get("updatedAt", ""),
                    source_archive_path=None,
                    license=license_info.get("spdxId", "") if isinstance(license_info, dict) else "",
                    maintainer=owner,
                    signed=False,
                    description=(repo.get("description", "") or "")[:500],
                    sources=["github"],
                    package_url=repo_url,
                    homepage_url=repo_url,
                    source_archive_url=github_archive_url(repo_url),
                )
            )
            if len(records) >= limit:
                return records
    return records


def load_spike_records(path: Path) -> list[ManifestRecord]:
    if not path.exists():
        return []
    data = json.loads(path.read_text())
    records: list[ManifestRecord] = []
    for item in data:
        repo = normalize_repo_url(item.get("repo_url", ""))
        registry = item.get("registry", "spike")
        records.append(
            ManifestRecord(
                id="",
                name=item.get("name", ""),
                registry=registry,
                repo_url=repo,
                version=item.get("version", ""),
                language=normalize_language(item.get("lang") or item.get("language")),
                install_count=int(item.get("stars") or item.get("downloads") or 0),
                last_update=item.get("updated_at", "") or item.get("last_update", ""),
                source_archive_path=None,
                license=item.get("license", ""),
                maintainer=item.get("maintainer", ""),
                signed=False,
                description=(item.get("description", "") or "")[:500],
                sources=[registry, "spike"],
                package_url="",
                homepage_url="",
                source_archive_url=github_archive_url(repo),
            )
        )
    return records


class ManifestBuilder:
    def __init__(
        self,
        repo_root: Path,
        snapshot_date: str,
        target_count: int = 500,
        download_archives: bool = False,
    ):
        self.repo_root = repo_root
        self.snapshot_date = snapshot_date
        self.target_count = target_count
        self.download_archives = download_archives
        self.corpus_dir = repo_root / "corpus"
        self.raw_dir = self.corpus_dir / "raw"

    def collect_records(self, *, offline: bool = False) -> list[ManifestRecord]:
        records: list[ManifestRecord] = []
        records.extend(load_spike_records(self.repo_root / "spike" / "results" / "scraped_corpus.json"))
        if offline:
            return merge_records(records)

        source_fetchers = [
            ("official", fetch_official_registry),
            ("smithery", fetch_smithery),
            ("npm", fetch_npm),
            ("pypi", fetch_pypi),
            ("github", fetch_github),
        ]
        for name, fetcher in source_fetchers:
            print(f"Fetching {name} records...", file=sys.stderr)
            try:
                records.extend(fetcher())
            except Exception as exc:  # keep partial corpus when one source is down
                print(f"WARNING: {name} fetch failed: {exc}", file=sys.stderr)
        return merge_records(records)

    def materialize_source_reference(self, record: ManifestRecord) -> None:
        if record.source_archive_path:
            return
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        existing = sorted(self.raw_dir.glob(f"{record.id}.*"))
        if existing:
            record.source_archive_path = existing[0].relative_to(self.corpus_dir).as_posix()
            return
        archive_url = record.source_archive_url
        if archive_url and self.download_archives:
            suffix = ".zip" if "github.com/repos/" in archive_url else Path(urllib.parse.urlparse(archive_url).path).suffix
            if not suffix:
                suffix = ".archive"
            target = self.raw_dir / f"{record.id}{suffix}"
            if not target.exists():
                try:
                    request = urllib.request.Request(
                        archive_url,
                        headers={"User-Agent": "mcp-bom-corpus-builder/1.0"},
                    )
                    with urllib.request.urlopen(request, timeout=45) as response:
                        target.write_bytes(response.read())
                except Exception:
                    target = self.write_metadata_snapshot(record)
            record.source_archive_path = target.relative_to(self.corpus_dir).as_posix()
            return
        target = self.write_metadata_snapshot(record)
        record.source_archive_path = target.relative_to(self.corpus_dir).as_posix()

    def write_metadata_snapshot(self, record: ManifestRecord) -> Path:
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        target = self.raw_dir / f"{record.id}.metadata.json"
        target.write_text(json.dumps(record.manifest_dict(), indent=2, sort_keys=True) + "\n")
        return target

    def write_manifest(self, records: list[ManifestRecord], output_path: Path | None = None) -> Path:
        self.corpus_dir.mkdir(parents=True, exist_ok=True)
        for record in records:
            if not record.id:
                record.id = stable_id(record.registry, record.name)
            self.materialize_source_reference(record)
        output = output_path or self.corpus_dir / "manifest.json"
        document = build_manifest_document(records, self.snapshot_date)
        output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
        return output


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot-date", required=True, help="Reproducibility date, e.g. 2026-05-01")
    parser.add_argument("--target-count", type=int, default=500)
    parser.add_argument("--offline", action="store_true", help="Use checked-in spike data only")
    parser.add_argument("--download-archives", action="store_true", help="Download source archives where available")
    parser.add_argument("--output", type=Path, default=Path("corpus/manifest.json"))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    repo_root = Path(__file__).resolve().parents[1]
    builder = ManifestBuilder(
        repo_root=repo_root,
        snapshot_date=args.snapshot_date,
        target_count=args.target_count,
        download_archives=args.download_archives,
    )
    records = builder.collect_records(offline=args.offline)
    selected = select_stratified(records, args.target_count)
    manifest_path = builder.write_manifest(selected, repo_root / args.output)
    print(f"Wrote {len(selected)} servers to {manifest_path}")
    if len(selected) < args.target_count:
        print(f"WARNING: target was {args.target_count}; only {len(selected)} unique servers found", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

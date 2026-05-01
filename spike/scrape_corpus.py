#!/usr/bin/env python3
"""
MCP-BOM Corpus Scraper
Scrapes MCP server metadata from npm, PyPI, and GitHub to build a 100+ server corpus.
"""

import requests
import json
import time
import os
from pathlib import Path

OUTPUT_DIR = Path(__file__).parent / "results"
OUTPUT_DIR.mkdir(exist_ok=True)

HEADERS = {"Accept": "application/json"}


def scrape_npm(queries, max_per_query=50):
    """Scrape npm registry for MCP server packages."""
    servers = {}
    for query in queries:
        print(f"  npm: searching '{query}'...")
        try:
            url = f"https://registry.npmjs.org/-/v1/search?text={query}&size={max_per_query}"
            resp = requests.get(url, headers=HEADERS, timeout=30)
            data = resp.json()
            for obj in data.get("objects", []):
                pkg = obj["package"]
                name = pkg["name"]
                if name in servers:
                    continue
                # Filter: must look like an MCP server
                desc = (pkg.get("description", "") or "").lower()
                if not any(k in desc or k in name.lower() for k in ["mcp", "model context protocol"]):
                    continue
                servers[name] = {
                    "name": name,
                    "registry": "npm",
                    "version": pkg.get("version", ""),
                    "description": (pkg.get("description", "") or "")[:200],
                    "repo_url": (pkg.get("links", {}).get("repository", "") or
                                 pkg.get("links", {}).get("homepage", "")),
                    "maintainer": (pkg.get("publisher", {}).get("username", "") or
                                   pkg.get("author", {}).get("name", "")),
                    "lang": "typescript",
                }
            time.sleep(0.5)
        except Exception as e:
            print(f"    ERROR: {e}")
    return servers


def scrape_pypi(queries, max_per_query=50):
    """Scrape PyPI for MCP server packages."""
    servers = {}
    for query in queries:
        print(f"  PyPI: searching '{query}'...")
        try:
            url = f"https://pypi.org/search/?q={query}&o="
            # PyPI doesn't have a great search API, use the simple JSON API instead
            # Search via the warehouse API
            resp = requests.get(f"https://pypi.org/simple/", timeout=30)
            # Fall back to known MCP packages on PyPI
            pass
        except Exception as e:
            print(f"    ERROR: {e}")

    # Use direct package lookups for known MCP packages
    known_pypi = [
        "mcp", "mcp-server-fetch", "mcp-server-git", "mcp-server-time",
        "mcp-server-sqlite", "mcp-server-postgres", "mcp-server-sentry",
        "mcp-server-docker", "mcp-shell-server", "mcp-server-mysql",
        "mcp-server-redis", "mcp-server-filesystem", "mcp-server-github",
        "mcp-server-slack", "mcp-server-brave-search", "mcp-server-gdrive",
        "mcp-server-memory", "mcp-server-puppeteer", "mcp-server-everything",
        "mcp-server-sequential-thinking", "mcp-server-aws-kb-retrieval",
        "mcp-server-langchain", "mcp-server-qdrant", "mcp-server-raygun",
        "mcp-server-airtable", "mcp-server-bigquery", "mcp-server-snowflake",
        "mcp-server-notion", "mcp-server-linear", "mcp-server-jira",
        "mcp-server-confluence", "mcp-server-stripe",
    ]
    for pkg_name in known_pypi:
        if pkg_name in servers:
            continue
        try:
            resp = requests.get(f"https://pypi.org/pypi/{pkg_name}/json", timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                info = data["info"]
                servers[pkg_name] = {
                    "name": pkg_name,
                    "registry": "pypi",
                    "version": info.get("version", ""),
                    "description": (info.get("summary", "") or "")[:200],
                    "repo_url": (info.get("home_page", "") or
                                 info.get("project_urls", {}).get("Repository", "") or
                                 info.get("project_urls", {}).get("Homepage", "") or ""),
                    "maintainer": info.get("author", "") or info.get("maintainer", ""),
                    "lang": "python",
                }
            time.sleep(0.3)
        except Exception as e:
            pass
    return servers


def scrape_github(queries, max_per_query=50):
    """Scrape GitHub for MCP server repositories using gh CLI."""
    import subprocess
    servers = {}
    for query in queries:
        print(f"  GitHub: searching '{query}'...")
        try:
            result = subprocess.run(
                ["gh", "search", "repos", query, "--limit", str(max_per_query),
                 "--json", "name,url,description,language,stargazersCount,updatedAt,owner"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                repos = json.loads(result.stdout)
                for repo in repos:
                    name = repo.get("name", "")
                    url = repo.get("url", "")
                    key = f"gh-{repo.get('owner', {}).get('login', 'unknown')}/{name}"
                    if key in servers:
                        continue
                    lang_raw = (repo.get("language", "") or "").lower()
                    lang = "python" if "python" in lang_raw else "typescript" if lang_raw in ["typescript", "javascript"] else lang_raw or "unknown"
                    servers[key] = {
                        "name": name,
                        "registry": "github",
                        "version": "",
                        "description": (repo.get("description", "") or "")[:200],
                        "repo_url": url,
                        "maintainer": repo.get("owner", {}).get("login", ""),
                        "lang": lang,
                        "stars": repo.get("stargazersCount", 0),
                        "updated_at": repo.get("updatedAt", ""),
                    }
            time.sleep(1)
        except Exception as e:
            print(f"    ERROR: {e}")
    return servers


def main():
    print("=" * 70)
    print("MCP-BOM CORPUS SCRAPER")
    print("=" * 70)

    all_servers = {}

    # npm scrape
    print("\n[1/3] Scraping npm...")
    npm_queries = [
        "@modelcontextprotocol", "mcp-server", "mcp server",
        "model context protocol server", "mcp-server-",
    ]
    npm_servers = scrape_npm(npm_queries)
    all_servers.update(npm_servers)
    print(f"  Found {len(npm_servers)} npm packages")

    # PyPI scrape
    print("\n[2/3] Scraping PyPI...")
    pypi_queries = ["mcp-server", "mcp server", "model context protocol"]
    pypi_servers = scrape_pypi(pypi_queries)
    all_servers.update(pypi_servers)
    print(f"  Found {len(pypi_servers)} PyPI packages")

    # GitHub scrape
    print("\n[3/3] Scraping GitHub...")
    gh_queries = [
        "mcp-server language:python stars:>10",
        "mcp-server language:typescript stars:>10",
        "mcp-server language:go stars:>10",
        "model-context-protocol server stars:>5",
    ]
    gh_servers = scrape_github(gh_queries)
    all_servers.update(gh_servers)
    print(f"  Found {len(gh_servers)} GitHub repos")

    # Summary
    print(f"\n{'='*70}")
    print(f"TOTAL: {len(all_servers)} unique MCP servers discovered")
    print(f"  npm:    {sum(1 for s in all_servers.values() if s['registry'] == 'npm')}")
    print(f"  PyPI:   {sum(1 for s in all_servers.values() if s['registry'] == 'pypi')}")
    print(f"  GitHub: {sum(1 for s in all_servers.values() if s['registry'] == 'github')}")

    # Language breakdown
    langs = {}
    for s in all_servers.values():
        l = s.get("lang", "unknown")
        langs[l] = langs.get(l, 0) + 1
    print(f"\n  Languages: {dict(sorted(langs.items(), key=lambda x: -x[1]))}")

    # Save
    corpus_path = OUTPUT_DIR / "scraped_corpus.json"
    with open(corpus_path, "w") as f:
        json.dump(list(all_servers.values()), f, indent=2)
    print(f"\nSaved: {corpus_path}")


if __name__ == "__main__":
    main()

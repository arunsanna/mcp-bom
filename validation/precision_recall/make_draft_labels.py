"""Generate AI-DRAFT ground-truth labels for the precision/recall sample.

THESE LABELS ARE NOT GROUND TRUTH. They are first-pass heuristic guesses
intended to give the human PI a starting point — review each one and either
accept (cp -> labels.json) or override (edit each suspect call) before
running score_metrics.py.

The heuristics encode the same rules described in
validation/precision_recall/README.md ("what counts as 'exposed' to the LLM").
They look at three signals per server:
  1. Tool-decorator hits in source ('@mcp.tool', '@server.tool', 'new Tool(',
     server.setRequestHandler(...), Tool() registrations).
  2. README text (domain hints — Notion, Slack, etc.).
  3. Entry-file imports (uvicorn/fastapi/express -> ingress; child_process /
     subprocess -> shell; mcp.ClientSession -> delegation).

Each label is paired with a one-line rationale so the PI can scan and override.
"""
from __future__ import annotations

import json
import re
import tempfile
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SAMPLE = REPO_ROOT / "validation" / "precision_recall" / "sample.json"
PRED = REPO_ROOT / "validation" / "precision_recall" / "predictions.json"
RAW = REPO_ROOT / "corpus" / "raw"
OUT = REPO_ROOT / "validation" / "precision_recall" / "labels.draft.json"

CATEGORIES = [
    "filesystem", "shell", "egress", "ingress",
    "secrets", "delegation", "impersonation", "data_sensitivity",
]


def _scan(root: Path) -> dict:
    """Pull text signals from a server's source tree (source already extracted)."""
    sigs: dict = {
        "tool_args": [],          # tool-call args / decorators
        "frameworks": set(),      # uvicorn, fastapi, express, hono, starlette
        "shell_calls": False,
        "ingress_hints": False,
        "client_session": False,
        "readme_text": "",
        "domain_hints": set(),
        "writes_files": False,
        "deletes_files": False,
        "fetches_url": False,
    }

    # README
    for p in sorted(root.rglob("README*")):
        if p.is_file() and p.stat().st_size < 200_000:
            try:
                sigs["readme_text"] = p.read_text(errors="ignore").lower()
                break
            except Exception:
                pass

    txt_blob_parts: list[str] = []
    for ext in ("py", "ts", "js", "go"):
        for p in list(root.rglob(f"*.{ext}"))[:80]:
            rel = p.relative_to(root).parts
            if any(part in {"node_modules", ".venv", "venv", "tests", "test", "__tests__", "examples", "docs", "vendor", "third_party"} for part in rel):
                continue
            try:
                t = p.read_text(errors="ignore")
            except Exception:
                continue
            txt_blob_parts.append(t)
    blob = "\n".join(txt_blob_parts)

    # tool decorators / registrations and surrounding context
    for m in re.finditer(r"@(?:mcp|server|tool|app)\.tool\b[^\n]{0,200}", blob):
        sigs["tool_args"].append(m.group(0)[:200])
    for m in re.finditer(r"new\s+Tool\s*\([^\)]{0,300}", blob):
        sigs["tool_args"].append(m.group(0)[:200])
    for m in re.finditer(r"server\.setRequestHandler\s*\(\s*CallToolRequestSchema[^\n]{0,300}", blob):
        sigs["tool_args"].append(m.group(0)[:200])
    for m in re.finditer(r"\.tool\s*\(\s*['\"][a-z0-9_\-]+['\"][^\)]{0,200}", blob, re.IGNORECASE):
        sigs["tool_args"].append(m.group(0)[:200])
    # FastMCP @mcp.tool() decorated function — capture next def line
    for m in re.finditer(r"@mcp\.tool[^\n]*\n(?:[^\n]*\n){0,3}\s*(?:async\s+)?def\s+(\w+)\(([^)]{0,300})\)", blob):
        sigs["tool_args"].append(f"{m.group(1)}({m.group(2)})")

    # framework / ingress
    for fw in ("uvicorn", "fastapi", "starlette", "express", "fastify", "hono", "flask", "aiohttp.web", "gin", "echo "):
        if fw in blob.lower():
            sigs["frameworks"].add(fw.strip())
    if re.search(r'host\s*=\s*["\']0\.0\.0\.0["\']', blob) or "0.0.0.0" in blob and any(fw in blob.lower() for fw in ("uvicorn", "createserver", ".listen(", "fastapi", "express")):
        sigs["ingress_hints"] = True

    # shell
    if re.search(r"\bsubprocess\.(run|Popen|call|check_output)\b|\bos\.system\b|\bchild_process\b|\bexecSync\b|\bexec\.Command\b|\bspawnSync\b", blob):
        sigs["shell_calls"] = True

    # delegation (server is itself an MCP client)
    if re.search(r"\bmcp\.ClientSession\b|\bClientSession\b\s*\(|@modelcontextprotocol/sdk.*[Cc]lient", blob):
        sigs["client_session"] = True

    # writes / deletes / fetches (in tool-decorated functions, ideally — heuristic uses whole blob)
    if re.search(r"\bopen\s*\([^)]*['\"]\s*[wa]b?[+]?", blob) or re.search(r"\bfs\.writeFile|\bos\.WriteFile\b", blob):
        sigs["writes_files"] = True
    if re.search(r"\bos\.remove\b|\bos\.unlink\b|\bshutil\.rmtree\b|\bfs\.unlink\b|\bos\.RemoveAll\b", blob):
        sigs["deletes_files"] = True
    if re.search(r"\brequests\.|\bhttpx\.|\bfetch\s*\(|\baxios\.|\bhttp\.Get\b", blob):
        sigs["fetches_url"] = True

    # domain hints from readme
    txt = sigs["readme_text"]
    for kw, dom in [
        ("notion", "notion"), ("slack", "slack"), ("github", "github"), ("gitlab", "gitlab"),
        ("jira", "jira"), ("salesforce", "salesforce"), ("hubspot", "hubspot"),
        ("stripe", "financial"), ("plaid", "financial"), ("paypal", "financial"),
        ("calendar", "calendar"), ("gmail", "email"), ("outlook", "email"),
        ("medical", "phi"), ("patient", "phi"), ("health", "phi"),
        ("location", "location"), ("address", "location"),
        ("twitter", "social"), ("reddit", "social"),
    ]:
        if kw in txt:
            sigs["domain_hints"].add(dom)

    return sigs


def _judge(sigs: dict, prediction: dict) -> dict:
    """Apply the labeling rules. Returns {category: (label, rationale)}."""
    out: dict = {}

    tool_blob = " ".join(sigs["tool_args"]).lower()

    # filesystem: tool with path/file/dir parameter, OR explicit FS-tool name keyword
    fs_tool_kw = any(kw in tool_blob for kw in (
        "path", "file", "dir", "folder", "read_file", "write_file", "delete", "ls", "list_files",
    ))
    if fs_tool_kw:
        out["filesystem"] = (True, "tool decorator references path/file/dir")
    elif sigs["writes_files"] or sigs["deletes_files"]:
        out["filesystem"] = (True, "writes or deletes files in source (likely exposed)")
    else:
        out["filesystem"] = (False, "no path/file tool argument detected")

    # shell: tool with command/exec/run keyword
    sh_tool_kw = any(kw in tool_blob for kw in (
        "command", "shell", "exec", "run_command", "execute", "script",
    ))
    if sh_tool_kw and sigs["shell_calls"]:
        out["shell"] = (True, "tool decorator references command/exec AND source uses subprocess")
    elif sh_tool_kw:
        out["shell"] = (True, "tool decorator references command/exec")
    else:
        out["shell"] = (False, "no command/exec tool argument detected")

    # egress: tool with url/fetch/search/query/api keyword OR fetches URLs
    eg_tool_kw = any(kw in tool_blob for kw in (
        "url", "fetch", "search", "query", "api", "request", "get_", "post_",
    ))
    if eg_tool_kw or sigs["fetches_url"]:
        out["egress"] = (True, "tool surface fetches URLs or queries APIs")
    else:
        out["egress"] = (False, "no fetch/api tool argument and no URL fetcher")

    # ingress: an HTTP server framework + 0.0.0.0 OR README says "HTTP server"
    if sigs["ingress_hints"] or "0.0.0.0" in " ".join(sigs["frameworks"]):
        out["ingress"] = (True, "binds 0.0.0.0 with an HTTP framework")
    elif {"uvicorn", "fastapi", "express", "fastify", "hono", "flask", "starlette", "aiohttp.web"} & sigs["frameworks"] and ("listen" in sigs["readme_text"] or "port" in sigs["readme_text"]):
        out["ingress"] = (True, "HTTP framework imported and README mentions listen/port")
    else:
        out["ingress"] = (False, "no public HTTP server detected (likely stdio)")

    # secrets: tool with env/secret/credential keyword
    sec_tool_kw = any(kw in tool_blob for kw in (
        "env", "secret", "credential", "vault", "keyring",
    ))
    out["secrets"] = (sec_tool_kw, "tool surface exposes env/secret access" if sec_tool_kw else "no env/secret tool argument; only Tier 1 config in source")

    # delegation: server itself imports ClientSession to call other MCP servers
    out["delegation"] = (
        sigs["client_session"],
        "imports MCP ClientSession (calls other MCP servers)" if sigs["client_session"]
        else "no MCP client import",
    )

    # impersonation: domain hints + write-shaped tool keywords
    write_tool_kw = any(kw in tool_blob for kw in (
        "create", "post", "send", "update", "comment", "delete", "edit", "publish", "reply",
    ))
    impersonation_domains = sigs["domain_hints"] & {
        "notion", "slack", "github", "gitlab", "jira", "salesforce", "hubspot",
        "email", "social",
    }
    if write_tool_kw and impersonation_domains:
        out["impersonation"] = (True, f"write-shaped tool ({sorted(impersonation_domains)}) acts on user's behalf")
    else:
        out["impersonation"] = (False, "no write-shaped tool against an external account system")

    # data_sensitivity: domain hints in {pii/phi/financial/location}
    sens_domains = sigs["domain_hints"] & {
        "phi", "financial", "location", "calendar", "email", "notion", "slack",
        "salesforce", "hubspot",
    }
    if sens_domains:
        out["data_sensitivity"] = (True, f"server domain handles sensitive data ({sorted(sens_domains)})")
    else:
        out["data_sensitivity"] = (False, "domain doesn't appear to handle PII/PHI/financial/location")

    return out


def main() -> int:
    sample = json.loads(SAMPLE.read_text())
    preds = {p["server_id"]: p for p in json.loads(PRED.read_text())}

    rows: list[dict] = []
    for s in sample["servers"]:
        sid = s["id"]
        if sid not in preds:
            continue
        zip_path = RAW / Path(s["source_archive_path"]).name
        if not zip_path.is_file():
            continue
        with tempfile.TemporaryDirectory() as t:
            with zipfile.ZipFile(zip_path) as zf:
                zf.extractall(t)
            root = Path(t)
            children = [p for p in root.iterdir() if p.is_dir()]
            if len(children) == 1 and not any(p.is_file() for p in root.iterdir()):
                root = children[0]
            sigs = _scan(root)

        judgments = _judge(sigs, preds[sid])
        rows.append({
            "server_id": sid,
            "repo_url": s.get("repo_url"),
            "source": "ai-draft",
            "labels": {cat: judgments[cat][0] for cat in CATEGORIES},
            "rationale": {cat: judgments[cat][1] for cat in CATEGORIES},
            "notes": "AI-drafted; human PI must review before computing real metrics",
        })

    OUT.write_text(json.dumps(rows, indent=2))
    print(f"Wrote {len(rows)} draft-labeled servers -> {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

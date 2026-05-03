"""MCP-BOM labeling helper — FastAPI web app."""

from __future__ import annotations

import csv
import io
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, StreamingResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates

# ── paths ─────────────────────────────────────────────────────────────
import os

DATA_SEED = Path(os.environ.get("DATA_SEED", "/app/data_seed"))
DB_PATH = Path(os.environ.get("DB_PATH", "/data/labels.db"))

VALIDATION_SET = DATA_SEED / "instrument_validation_set.json"
SIGNALS_DIR = DATA_SEED / "labeling_signals"

CATEGORIES = [
    "filesystem", "shell", "egress", "ingress",
    "secrets", "delegation", "impersonation", "data_sensitivity",
]

# ── load seed data at boot ────────────────────────────────────────────
with open(VALIDATION_SET) as f:
    _val = json.load(f)
SERVERS = _val["servers"]
SERVER_MAP = {s["server_id"]: s for s in SERVERS}

SIGNALS: dict[str, dict] = {}
if SIGNALS_DIR.exists():
    for p in SIGNALS_DIR.glob("*.json"):
        d = json.loads(p.read_text())
        SIGNALS[d["server_id"]] = d

# ── sqlite init ───────────────────────────────────────────────────────
def _get_db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS labels (
            server_id TEXT PRIMARY KEY,
            filesystem INTEGER,
            shell INTEGER,
            egress INTEGER,
            ingress INTEGER,
            secrets INTEGER,
            delegation INTEGER,
            impersonation INTEGER,
            data_sensitivity INTEGER,
            notes TEXT,
            updated_at TEXT
        )
    """)
    conn.commit()
    return conn


def _get_label(conn: sqlite3.Connection, server_id: str) -> dict | None:
    row = conn.execute(
        "SELECT * FROM labels WHERE server_id = ?", (server_id,)
    ).fetchone()
    if not row:
        return None
    cols = ["server_id"] + CATEGORIES + ["notes", "updated_at"]
    return dict(zip(cols, row))


def _all_labels(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute("SELECT * FROM labels ORDER BY server_id").fetchall()
    cols = ["server_id"] + CATEGORIES + ["notes", "updated_at"]
    return [dict(zip(cols, r)) for r in rows]


def _is_complete(label: dict | None) -> bool:
    if label is None:
        return False
    return all(label.get(c) is not None for c in CATEGORIES)


# ── app ───────────────────────────────────────────────────────────────
app = FastAPI(title="MCP-BOM Labeler")
templates = Jinja2Templates(directory=Path(__file__).parent / "templates")


@app.get("/healthz", response_class=PlainTextResponse)
async def healthz():
    return "ok"


@app.get("/", response_class=HTMLResponse)
async def list_servers(request: Request):
    conn = _get_db()
    try:
        labels = {r["server_id"]: r for r in _all_labels(conn)}
        rows = []
        for s in SERVERS:
            sid = s["server_id"]
            label = labels.get(sid)
            sig = SIGNALS.get(sid, {})
            evidence_count = sum(
                len(v) for v in sig.get("categories", {}).values()
            )
            rows.append({
                "server_id": sid,
                "source": s.get("source", ""),
                "source_tier": s.get("source_tier", ""),
                "labeled": _is_complete(label),
                "evidence_count": evidence_count,
                "files_scanned": sig.get("stats", {}).get("total_files_scanned", 0),
            })
        labeled_count = sum(1 for r in rows if r["labeled"])
        return templates.TemplateResponse("list.html", {
            "request": request,
            "rows": rows,
            "labeled_count": labeled_count,
            "total": len(SERVERS),
        })
    finally:
        conn.close()


@app.get("/server/{server_id}", response_class=HTMLResponse)
async def server_detail(request: Request, server_id: str):
    if server_id not in SERVER_MAP:
        return PlainTextResponse("Server not found", status_code=404)
    conn = _get_db()
    try:
        label = _get_label(conn, server_id)
        sig = SIGNALS.get(server_id, {"categories": {}, "stats": {}})
        meta = SERVER_MAP[server_id]

        # Find next unlabeled server
        next_id = None
        for s in SERVERS:
            sid = s["server_id"]
            if sid == server_id:
                continue
            if not _is_complete(_get_label(conn, sid)):
                next_id = sid
                break

        return templates.TemplateResponse("server.html", {
            "request": request,
            "server_id": server_id,
            "meta": meta,
            "signals": sig,
            "label": label,
            "categories": CATEGORIES,
            "next_id": next_id,
        })
    finally:
        conn.close()


@app.post("/server/{server_id}")
async def save_label(
    server_id: str,
    filesystem: str = Form(""),
    shell: str = Form(""),
    egress: str = Form(""),
    ingress: str = Form(""),
    secrets: str = Form(""),
    delegation: str = Form(""),
    impersonation: str = Form(""),
    data_sensitivity: str = Form(""),
    notes: str = Form(""),
):
    if server_id not in SERVER_MAP:
        return PlainTextResponse("Server not found", status_code=404)

    def _int_or_none(v: str) -> int | None:
        if v in ("0", "1"):
            return int(v)
        return None

    values = {
        "filesystem": _int_or_none(filesystem),
        "shell": _int_or_none(shell),
        "egress": _int_or_none(egress),
        "ingress": _int_or_none(ingress),
        "secrets": _int_or_none(secrets),
        "delegation": _int_or_none(delegation),
        "impersonation": _int_or_none(impersonation),
        "data_sensitivity": _int_or_none(data_sensitivity),
        "notes": notes.strip(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }

    conn = _get_db()
    try:
        cols = ["server_id"] + list(values.keys())
        placeholders = ",".join(["?"] * len(cols))
        updates = ", ".join(f"{c}=excluded.{c}" for c in values.keys())
        sql = f"INSERT INTO labels ({','.join(cols)}) VALUES ({placeholders}) ON CONFLICT(server_id) DO UPDATE SET {updates}"
        conn.execute(sql, [server_id] + list(values.values()))
        conn.commit()
    finally:
        conn.close()

    # Find next unlabeled
    conn = _get_db()
    try:
        next_id = None
        for s in SERVERS:
            sid = s["server_id"]
            if sid == server_id:
                continue
            if not _is_complete(_get_label(conn, sid)):
                next_id = sid
                break
    finally:
        conn.close()

    if next_id:
        from fastapi.responses import RedirectResponse
        return RedirectResponse(f"/server/{next_id}", status_code=303)
    return RedirectResponse("/", status_code=303)


@app.get("/api/progress")
async def progress():
    conn = _get_db()
    try:
        labels = {r["server_id"]: r for r in _all_labels(conn)}
        labeled = sum(1 for s in SERVERS if _is_complete(labels.get(s["server_id"])))
        by_server = {}
        for s in SERVERS:
            sid = s["server_id"]
            lbl = labels.get(sid)
            if lbl:
                by_server[sid] = {c: lbl.get(c) for c in CATEGORIES}
            else:
                by_server[sid] = {}
        return {
            "labeled": labeled,
            "total": len(SERVERS),
            "by_server": by_server,
        }
    finally:
        conn.close()


@app.get("/api/export.csv")
async def export_csv():
    conn = _get_db()
    try:
        labels = {r["server_id"]: r for r in _all_labels(conn)}
        output = io.StringIO()
        writer = csv.writer(output)
        header = [
            "server_id", "source", "source_tier", "raw_archive_path",
        ] + CATEGORIES + ["notes"]
        writer.writerow(header)
        for s in SERVERS:
            sid = s["server_id"]
            lbl = labels.get(sid)
            row = [sid, s.get("source", ""), s.get("source_tier", ""),
                   s.get("raw_archive_path", "")]
            for c in CATEGORIES:
                v = lbl.get(c) if lbl else None
                row.append(v if v is not None else "")
            row.append(lbl.get("notes", "") if lbl else "")
            writer.writerow(row)
        output.seek(0)
        return StreamingResponse(
            io.BytesIO(output.getvalue().encode("utf-8")),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=labels_arun.csv"},
        )
    finally:
        conn.close()

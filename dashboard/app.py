#!/usr/bin/env python3
"""dashboard/app.py — MCPWarden real-time dashboard server."""

import json
import queue
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path

ROOT      = Path(__file__).parent.parent
AUDIT_LOG = ROOT / "logs" / "audit.jsonl"
STATIC    = Path(__file__).parent

try:
    from flask import Flask, Response, jsonify, request, send_from_directory
except ImportError:
    raise SystemExit("❌  pip install flask")

app = Flask(__name__)

_logs: list[dict] = []
_subs: list[queue.Queue] = []
_lock = threading.Lock()


# ── Category inference for old log entries that predate the field ─────────────

def _parse_ts(ts_str: str) -> datetime:
    if not ts_str:
        return datetime.min.replace(tzinfo=timezone.utc)
    try:
        return datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
    except Exception:
        return datetime.min.replace(tzinfo=timezone.utc)


def _infer_category(entry: dict) -> str:
    cat = entry.get("category")
    if cat and cat != "unknown":
        return cat
    tool   = (entry.get("tool") or "").lower()
    detail = entry.get("detail") or ""
    if tool in ("read_env", "env_read", "env_access"):
        return "credential"
    if tool == "fetch_url":
        return "network"
    if tool in ("file_read", "file_write", "delete_file",
                "list_directory", "read_file", "write_file"):
        sensitive = (".ssh", ".aws", ".env", "credentials",
                     "secrets", "gnupg", "gcloud", "keychain", "id_rsa")
        return "credential" if any(p in detail for p in sensitive) else "filesystem"
    if tool in ("bash", "run_bash", "run_command"):
        return "shell"
    return "unknown"


def _enrich(entry: dict) -> dict:
    if not entry.get("category") or entry["category"] == "unknown":
        entry = dict(entry)
        entry["category"] = _infer_category(entry)
    return entry


# ── Log watcher ───────────────────────────────────────────────────────────────

def _load_existing() -> list[dict]:
    if not AUDIT_LOG.exists():
        return []
    out = []
    with open(AUDIT_LOG) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    out.append(_enrich(json.loads(line)))
                except json.JSONDecodeError:
                    pass
    return out


def _watch():
    global _logs
    _logs = _load_existing()
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    AUDIT_LOG.touch()
    with open(AUDIT_LOG) as fh:
        fh.seek(0, 2)
        while True:
            line = fh.readline()
            if line:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = _enrich(json.loads(line))
                    with _lock:
                        _logs.append(entry)
                    for q in list(_subs):
                        try:
                            q.put_nowait(entry)
                        except queue.Full:
                            pass
                except json.JSONDecodeError:
                    pass
            else:
                time.sleep(0.3)


threading.Thread(target=_watch, daemon=True).start()


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory(str(STATIC), "index.html")


@app.route("/api/logs")
def get_logs():
    category = request.args.get("category", "all")
    with _lock:
        entries = list(_logs)
    if category != "all":
        entries = [e for e in entries if (e.get("category") or "unknown") == category]
    return jsonify(entries[-300:])


@app.route("/api/stats")
def get_stats():
    with _lock:
        entries = list(_logs)

    total   = len(entries)
    allowed = sum(1 for e in entries if e.get("verdict") == "allow")
    blocked = sum(1 for e in entries if e.get("verdict") == "block")

    by_tool     = defaultdict(lambda: {"allow": 0, "block": 0})
    by_category = defaultdict(lambda: {"allow": 0, "block": 0})

    for e in entries:
        v = e.get("verdict", "")
        if v not in ("allow", "block"):
            continue
        t   = e.get("tool")     or "unknown"
        cat = e.get("category") or "unknown"
        by_tool[t][v]      += 1
        by_category[cat][v] += 1

    timeline = defaultdict(lambda: {"allow": 0, "block": 0})
    for e in entries:
        ts = (e.get("ts") or "")[:16]
        v  = e.get("verdict", "")
        if v in ("allow", "block"):
            timeline[ts][v] += 1

    # ── Last-24h stats ────────────────────────────────────────────────────────
    now    = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=24)
    recent = [e for e in entries if _parse_ts(e.get("ts")) >= cutoff]

    r_total   = len(recent)
    r_allowed = sum(1 for e in recent if e.get("verdict") == "allow")
    r_blocked = sum(1 for e in recent if e.get("verdict") == "block")

    r_by_tool     = defaultdict(lambda: {"allow": 0, "block": 0})
    r_by_category = defaultdict(lambda: {"allow": 0, "block": 0})
    for e in recent:
        v = e.get("verdict", "")
        if v not in ("allow", "block"):
            continue
        r_by_tool[e.get("tool") or "unknown"][v]            += 1
        r_by_category[e.get("category") or "unknown"][v]   += 1

    hourly_map: dict = defaultdict(lambda: {"allow": 0, "block": 0})
    for e in recent:
        ts = _parse_ts(e.get("ts"))
        hk = ts.replace(minute=0, second=0, microsecond=0).isoformat()
        v  = e.get("verdict", "")
        if v in ("allow", "block"):
            hourly_map[hk][v] += 1

    now_h  = now.replace(minute=0, second=0, microsecond=0)
    hourly = []
    for i in range(23, -1, -1):
        t  = now_h - timedelta(hours=i)
        hk = t.isoformat()
        h  = hourly_map.get(hk, {"allow": 0, "block": 0})
        hourly.append({"label": t.strftime("%H:00"), "allow": h["allow"], "block": h["block"]})

    return jsonify({
        "total":       total,
        "allowed":     allowed,
        "blocked":     blocked,
        "by_tool":     dict(by_tool),
        "by_category": dict(by_category),
        "timeline":    dict(sorted(timeline.items())[-30:]),
        "last_24h": {
            "total":       r_total,
            "allowed":     r_allowed,
            "blocked":     r_blocked,
            "hourly":      hourly,
            "by_tool":     dict(r_by_tool),
            "by_category": dict(r_by_category),
        },
    })


@app.route("/api/stream")
def stream():
    q = queue.Queue(maxsize=200)
    with _lock:
        _subs.append(q)

    def generate():
        try:
            while True:
                try:
                    entry = q.get(timeout=20)
                    yield f"data: {json.dumps(entry)}\n\n"
                except queue.Empty:
                    yield ": ping\n\n"
        finally:
            with _lock:
                if q in _subs:
                    _subs.remove(q)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


if __name__ == "__main__":
    print(f"\n🔥  MCPWarden Dashboard")
    print(f"    Open  →  http://127.0.0.1:8050")
    print(f"    Log   →  {AUDIT_LOG}\n")
    app.run(host="127.0.0.1", port=8050, debug=False, threaded=True)

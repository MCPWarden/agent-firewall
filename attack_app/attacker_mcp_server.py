#!/usr/bin/env python3
"""
attack_app/attacker_mcp_server.py
Naive third-party MCP server — zero security checks.
Now includes fetch_url for web access.
"""

import json
import os
import subprocess
import sys
import urllib.request
import urllib.error
from pathlib import Path


def _send(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()

def _result(id_, content):
    _send({"jsonrpc": "2.0", "id": id_, "result": content})

def _error(id_, code, message):
    _send({"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}})


TOOLS = [
    {
        "name": "read_file",
        "description": "Read any file on the filesystem.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "write_file",
        "description": "Write content to any file.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
            "required": ["path", "content"],
        },
    },
    {
        "name": "run_command",
        "description": "Run any shell command.",
        "inputSchema": {
            "type": "object",
            "properties": {"command": {"type": "string"}, "cwd": {"type": "string", "default": "."}},
            "required": ["command"],
        },
    },
    {
        "name": "read_env",
        "description": "Read an environment variable.",
        "inputSchema": {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        },
    },
    {
        "name": "list_directory",
        "description": "List files in a directory.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "fetch_url",
        "description": "Fetch content from a URL (web scraping / HTTP requests).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url":           {"type": "string", "description": "Full URL to fetch"},
                "max_chars":     {"type": "integer", "default": 2000,
                                  "description": "Max characters of response to return"},
            },
            "required": ["url"],
        },
    },
]


def handle_read_file(args):
    try:
        content = Path(args["path"]).expanduser().read_text(errors="replace")
        return {"content": [{"type": "text", "text": content}]}
    except Exception as e:
        return {"isError": True, "content": [{"type": "text", "text": str(e)}]}

def handle_write_file(args):
    try:
        p = Path(args["path"]).expanduser()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(args["content"])
        return {"content": [{"type": "text", "text": f"Written to {args['path']}"}]}
    except Exception as e:
        return {"isError": True, "content": [{"type": "text", "text": str(e)}]}

def handle_run_command(args):
    try:
        r = subprocess.run(args["command"], shell=True, capture_output=True,
                           text=True, cwd=os.path.expanduser(args.get("cwd",".")), timeout=30)
        out = r.stdout + (f"\nSTDERR:\n{r.stderr}" if r.stderr else "")
        return {"content": [{"type": "text", "text": out or "(no output)"}]}
    except Exception as e:
        return {"isError": True, "content": [{"type": "text", "text": str(e)}]}

def handle_read_env(args):
    name = args["name"]
    val  = os.environ.get(name)
    return {"content": [{"type": "text", "text": f"{name}={val}" if val else f"{name} is not set"}]}

def handle_list_directory(args):
    try:
        entries = sorted(Path(args["path"]).expanduser().iterdir())
        lines   = [("DIR  " if e.is_dir() else "FILE ") + e.name for e in entries]
        return {"content": [{"type": "text", "text": "\n".join(lines) or "(empty)"}]}
    except Exception as e:
        return {"isError": True, "content": [{"type": "text", "text": str(e)}]}

def handle_fetch_url(args):
    url       = args["url"]
    max_chars = int(args.get('max_chars', 2000))
    try:
        import ssl as _ssl
        # Bypass macOS cert store — required for demo on macOS without cert install
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = _ssl.CERT_NONE
        req = urllib.request.Request(
            url, headers={"User-Agent": "MCPWarden/1.0"},
        )
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            raw          = resp.read(max_chars * 4)
            content_type = resp.headers.get("Content-Type", "")
            charset      = "utf-8"
            if "charset=" in content_type:
                charset = content_type.split("charset=")[-1].split(";")[0].strip()
            text = raw.decode(charset, errors='replace')[:max_chars]
            return {
                "content": [{"type": "text",
                             "text": f"[{resp.status} {resp.reason}]  {url}\n\n{text}"}]
            }
    except urllib.error.HTTPError as e:
        return {"isError": True,
                "content": [{"type": "text", "text": f"HTTP {e.code}: {e.reason}  {url}"}]}
    except urllib.error.URLError as e:
        return {"isError": True,
                "content": [{"type": "text", "text": f"URL error: {e.reason}  {url}"}]}
    except Exception as e:
        return {"isError": True, "content": [{"type": "text", "text": str(e)}]}

DISPATCH = {
    "read_file":      handle_read_file,
    "write_file":     handle_write_file,
    "run_command":    handle_run_command,
    "read_env":       handle_read_env,
    "list_directory": handle_list_directory,
    "fetch_url":      handle_fetch_url,
}

def main():
    print("[attacker-mcp] started", file=sys.stderr)
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            continue
        msg_id = msg.get("id")
        method = msg.get("method", "")
        params = msg.get("params", {})

        if method == "initialize":
            _result(msg_id, {"protocolVersion": "2024-11-05",
                             "serverInfo": {"name": "attacker-mcp", "version": "1.1.0"},
                             "capabilities": {"tools": {}}})
        elif method == "tools/list":
            _result(msg_id, {"tools": TOOLS})
        elif method == "tools/call":
            name = params.get("name")
            args = params.get("arguments", {})
            if name not in DISPATCH:
                _error(msg_id, -32601, f"Unknown tool: {name}")
            else:
                _result(msg_id, DISPATCH[name](args))
        elif method == "notifications/initialized":
            pass
        else:
            _error(msg_id, -32601, f"Method not found: {method}")

if __name__ == "__main__":
    main()
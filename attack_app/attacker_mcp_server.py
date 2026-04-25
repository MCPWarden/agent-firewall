#!/usr/bin/env python3
"""
attack_app/attacker_mcp_server.py
Simulates a naive third-party MCP server with zero security checks.
The Agent Firewall proxy intercepts every call before it reaches here.
"""

import json
import os
import subprocess
import sys
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
    text = f"{name}={val}" if val else f"{name} is not set"
    return {"content": [{"type": "text", "text": text}]}

def handle_list_directory(args):
    try:
        entries = sorted(Path(args["path"]).expanduser().iterdir())
        lines   = [("DIR  " if e.is_dir() else "FILE ") + e.name for e in entries]
        return {"content": [{"type": "text", "text": "\n".join(lines) or "(empty)"}]}
    except Exception as e:
        return {"isError": True, "content": [{"type": "text", "text": str(e)}]}

DISPATCH = {
    "read_file":      handle_read_file,
    "write_file":     handle_write_file,
    "run_command":    handle_run_command,
    "read_env":       handle_read_env,
    "list_directory": handle_list_directory,
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
                             "serverInfo": {"name": "attacker-mcp", "version": "1.0.0"},
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
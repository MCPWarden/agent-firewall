#!/usr/bin/env python3
"""
agent_firewall/src/mcp_server.py
──────────────────────────────────
MCP (Model Context Protocol) server that wraps dangerous tools with
firewall checks. Drop this into your VSCode MCP config to intercept
Claude's tool calls before they touch your filesystem.

On BLOCK the server returns a structured error that instructs the agent
to stop the current task entirely, halting the VSCode chat.

Usage:
  python mcp_server.py --config config/policy.yaml

VSCode MCP config (settings.json):
  "mcp": {
    "servers": {
      "agent-firewall": {
        "command": "python",
        "args": ["/path/to/agent-firewall/src/mcp_server.py"],
        "env": { "PROJECT_ROOT": "${workspaceFolder}" }
      }
    }
  }
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from firewall import AgentFirewall, Verdict

# ── MCP helpers ────────────────────────────────────────────────────────────────

def _send(obj: dict):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()

def _error(id_, code: int, message: str):
    _send({"jsonrpc": "2.0", "id": id_,
           "error": {"code": code, "message": message}})

def _result(id_, content):
    _send({"jsonrpc": "2.0", "id": id_, "result": content})


# ── Blocked response – instructs the agent to STOP ────────────────────────────

_STOP_INSTRUCTIONS = (
    "\n\n---\n"
    "🔴 **AGENT FIREWALL – ACTION BLOCKED**\n\n"
    "The user has denied this action via the Agent Firewall popup.\n"
    "**You must stop the current task immediately.** Do not attempt to work around "
    "this restriction or retry the blocked operation. Do not continue with any "
    "further tool calls related to this task.\n\n"
    "Wait for the user to give you new instructions before proceeding.\n"
    "---"
)

def _blocked_response(reason: str) -> dict:
    """
    Returns an MCP tool result that signals a hard stop to the agent.
    isError=True causes VSCode / Claude to treat this as a terminal failure
    and stop the current agentic loop.
    """
    return {
        "isError": True,
        "content": [{
            "type": "text",
            "text": f"🚫 BLOCKED by Agent Firewall: {reason}{_STOP_INSTRUCTIONS}",
        }],
    }


# ── Tool definitions ───────────────────────────────────────────────────────────

TOOLS = [
    {
        "name": "read_file",
        "description": "Read the contents of a file. Intercepted by Agent Firewall.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Absolute or relative file path"}
            },
            "required": ["path"],
        },
    },
    {
        "name": "write_file",
        "description": "Write content to a file. Intercepted by Agent Firewall.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path":    {"type": "string"},
                "content": {"type": "string"},
            },
            "required": ["path", "content"],
        },
    },
    {
        "name": "delete_file",
        "description": "Delete a file. Intercepted by Agent Firewall.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"}
            },
            "required": ["path"],
        },
    },
    {
        "name": "run_bash",
        "description": "Run a shell command. Intercepted by Agent Firewall.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command":     {"type": "string", "description": "Shell command to execute"},
                "cwd":         {"type": "string", "description": "Working directory", "default": "."},
                "timeout_sec": {"type": "integer", "default": 30},
            },
            "required": ["command"],
        },
    },
    {
        "name": "list_directory",
        "description": "List files in a directory.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"}
            },
            "required": ["path"],
        },
    },
]


# ── Tool handlers ──────────────────────────────────────────────────────────────

def handle_read_file(fw: AgentFirewall, args: dict) -> dict:
    path     = args["path"]
    decision = fw.check_file_read(path)

    if decision.verdict == Verdict.BLOCK:
        return _blocked_response(decision.reason)

    warning_prefix = ""
    if decision.verdict == Verdict.WARN:
        warning_prefix = f"⚠️  WARNING: {decision.reason}\n\n"

    try:
        content = Path(path).expanduser().read_text(errors="replace")
        return {"content": [{"type": "text", "text": warning_prefix + content}]}
    except FileNotFoundError:
        return {"isError": True,
                "content": [{"type": "text", "text": f"File not found: {path}"}]}
    except PermissionError:
        return {"isError": True,
                "content": [{"type": "text", "text": f"Permission denied: {path}"}]}


def handle_write_file(fw: AgentFirewall, args: dict) -> dict:
    path     = args["path"]
    content  = args["content"]
    decision = fw.check_file_write(path, size_bytes=len(content.encode()))

    if decision.verdict == Verdict.BLOCK:
        return _blocked_response(decision.reason)

    try:
        p = Path(path).expanduser()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        return {"content": [{"type": "text",
                              "text": f"✅ Written {len(content)} chars to {path}"}]}
    except Exception as e:
        return {"isError": True, "content": [{"type": "text", "text": str(e)}]}


def handle_delete_file(fw: AgentFirewall, args: dict) -> dict:
    path     = args["path"]
    decision = fw.check_file_delete(path)

    if decision.verdict == Verdict.BLOCK:
        return _blocked_response(decision.reason)

    try:
        Path(path).expanduser().unlink()
        return {"content": [{"type": "text", "text": f"✅ Deleted {path}"}]}
    except Exception as e:
        return {"isError": True, "content": [{"type": "text", "text": str(e)}]}


def handle_run_bash(fw: AgentFirewall, args: dict) -> dict:
    cmd      = args["command"]
    cwd      = args.get("cwd", ".")
    timeout  = args.get("timeout_sec", 30)
    decision = fw.check_bash(cmd)

    if decision.verdict == Verdict.BLOCK:
        return _blocked_response(decision.reason)

    warn_prefix = ""
    if decision.verdict == Verdict.WARN:
        warn_prefix = f"⚠️  WARNING: {decision.reason}\n"

    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            cwd=os.path.expanduser(cwd), timeout=timeout,
        )
        output = result.stdout + (f"\nSTDERR:\n{result.stderr}" if result.stderr else "")
        return {
            "content": [{"type": "text", "text": warn_prefix + output}],
            "meta":    {"exit_code": result.returncode},
        }
    except subprocess.TimeoutExpired:
        return {"isError": True,
                "content": [{"type": "text",
                              "text": f"Command timed out after {timeout}s"}]}
    except Exception as e:
        return {"isError": True, "content": [{"type": "text", "text": str(e)}]}


def handle_list_directory(fw: AgentFirewall, args: dict) -> dict:
    path     = args["path"]
    decision = fw.check_file_read(path)   # reuse read policy for listing

    if decision.verdict == Verdict.BLOCK:
        return _blocked_response(decision.reason)

    try:
        entries = sorted(Path(path).expanduser().iterdir())
        lines   = [("📁 " if e.is_dir() else "📄 ") + e.name for e in entries]
        return {"content": [{"type": "text", "text": "\n".join(lines)}]}
    except Exception as e:
        return {"isError": True, "content": [{"type": "text", "text": str(e)}]}


# ── Main server loop ───────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Agent Firewall MCP Server")
    parser.add_argument("--config", default="config/policy.yaml")
    parsed = parser.parse_args()

    config_path = Path(parsed.config)
    if not config_path.exists():
        config_path = Path(__file__).parent.parent / parsed.config

    fw = AgentFirewall(config_path)
    print(f"🔥 Agent Firewall MCP server started (policy: {config_path})", file=sys.stderr)

    dispatch = {
        "read_file":      handle_read_file,
        "write_file":     handle_write_file,
        "delete_file":    handle_delete_file,
        "run_bash":       handle_run_bash,
        "list_directory": handle_list_directory,
    }

    for raw_line in sys.stdin:
        raw_line = raw_line.strip()
        if not raw_line:
            continue

        try:
            msg = json.loads(raw_line)
        except json.JSONDecodeError:
            continue

        msg_id = msg.get("id")
        method = msg.get("method", "")
        params = msg.get("params", {})

        if method == "initialize":
            _result(msg_id, {
                "protocolVersion": "2024-11-05",
                "serverInfo":      {"name": "agent-firewall", "version": "1.1.0"},
                "capabilities":    {"tools": {}},
            })

        elif method == "tools/list":
            _result(msg_id, {"tools": TOOLS})

        elif method == "tools/call":
            tool_name = params.get("name")
            tool_args = params.get("arguments", {})

            if tool_name not in dispatch:
                _error(msg_id, -32601, f"Unknown tool: {tool_name}")
            else:
                result = dispatch[tool_name](fw, tool_args)
                _result(msg_id, result)

        elif method == "notifications/initialized":
            pass

        else:
            _error(msg_id, -32601, f"Method not found: {method}")


if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
src/firewall_proxy.py
──────────────────────
Silent background TCP proxy.

Sits between ANY MCP client (external IDE, PyCharm, IntelliJ agent) and
the real MCP server. Every tool call passes through the Agent Firewall
before reaching the backend.

Usage:
  python src/firewall_proxy.py --config config/policy.yaml --port 9999
"""

import asyncio
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from firewall import AgentFirewall, Verdict

HOST = "127.0.0.1"


def _evaluate(fw: AgentFirewall, tool_name: str, args: dict):
    if tool_name == "read_file":
        return fw.check_file_read(args.get("path", ""))
    if tool_name == "write_file":
        return fw.check_file_write(args.get("path", ""), len(args.get("content", "").encode()))
    if tool_name in ("run_command", "run_bash", "bash"):
        return fw.check_bash(args.get("command", args.get("cmd", "")))
    if tool_name == "read_env":
        return fw.check_env_access(args.get("name", args.get("var", "")))
    if tool_name == "list_directory":
        return fw.check_file_read(args.get("path", ""))
    from firewall import Decision, Verdict as V
    return Decision(V.ALLOW, f"Tool '{tool_name}' not in firewall scope")


_STOP_MSG = (
    "\n\n---\n"
    "🔴 **AGENT FIREWALL – ACTION BLOCKED**\n\n"
    "The user denied this action. Stop the current task immediately.\n"
    "Do not retry or work around this. Wait for new instructions.\n"
    "---"
)

def _blocked_result(msg_id, reason: str) -> bytes:
    resp = {
        "jsonrpc": "2.0",
        "id": msg_id,
        "result": {
            "isError": True,
            "content": [{"type": "text",
                          "text": f"🚫 BLOCKED by Agent Firewall: {reason}{_STOP_MSG}"}],
        },
    }
    return (json.dumps(resp) + "\n").encode()


class FirewallProxy:
    def __init__(self, fw: AgentFirewall, backend_cmd: list):
        self.fw          = fw
        self.backend_cmd = backend_cmd

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        print(f"[Proxy] ✅ Client connected: {addr}", file=sys.stderr)

        backend = await asyncio.create_subprocess_exec(
            *self.backend_cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=sys.stderr,
        )

        async def forward(line: bytes, wants_response: bool):
            """Send to backend; only wait for a reply when the message has an id."""
            backend.stdin.write(line.rstrip(b"\n") + b"\n")
            await backend.stdin.drain()
            if wants_response:
                return await backend.stdout.readline()
            return None

        try:
            while True:
                line = await reader.readline()
                if not line:
                    break

                try:
                    msg = json.loads(line.decode())
                except json.JSONDecodeError:
                    continue

                method = msg.get("method", "")
                msg_id = msg.get("id")                    # None for notifications
                is_request = msg_id is not None           # requests have an id

                # ── Intercept tool calls ───────────────────────────────────
                if method == "tools/call" and is_request:
                    tool_name = msg.get("params", {}).get("name", "")
                    tool_args = msg.get("params", {}).get("arguments", {})

                    print(f"[Proxy] 🔍 {tool_name}  args={tool_args}", file=sys.stderr)

                    decision = _evaluate(self.fw, tool_name, tool_args)

                    if decision.verdict == Verdict.BLOCK:
                        print(f"[Proxy] 🚫 BLOCKED: {decision.reason}", file=sys.stderr)
                        writer.write(_blocked_result(msg_id, decision.reason))
                        await writer.drain()
                        continue

                    if decision.verdict == Verdict.WARN:
                        print(f"[Proxy] ⚠️  WARN (allowed): {decision.reason}", file=sys.stderr)
                    else:
                        print(f"[Proxy] ✅ allowed → forwarding", file=sys.stderr)

                # ── Forward to backend ─────────────────────────────────────
                # Notifications (no id) get forwarded but we don't wait for a reply
                response = await forward(line, wants_response=is_request)
                if response:
                    writer.write(response)
                    await writer.drain()

        except asyncio.IncompleteReadError:
            pass
        except Exception as e:
            print(f"[Proxy] ❌ Error: {e}", file=sys.stderr)
        finally:
            try:
                backend.terminate()
                await backend.wait()
            except Exception:
                pass
            writer.close()
            print(f"[Proxy] Client disconnected: {addr}", file=sys.stderr)


async def main():
    parser = argparse.ArgumentParser(description="Agent Firewall TCP Proxy")
    parser.add_argument("--config",  default="config/policy.yaml")
    parser.add_argument("--port",    type=int, default=9999)
    parser.add_argument("--backend", default=None)
    args = parser.parse_args()

    config_path = Path(args.config)
    if not config_path.exists():
        config_path = Path(__file__).parent.parent / args.config

    fw = AgentFirewall(config_path)

    backend_script = args.backend or str(Path(__file__).parent / "attacker_mcp_server.py")
    backend_cmd    = [sys.executable, backend_script]

    proxy  = FirewallProxy(fw, backend_cmd)
    server = await asyncio.start_server(proxy.handle, HOST, args.port)

    print(f"\n🔥  Agent Firewall Proxy", file=sys.stderr)
    print(f"    Listening : {HOST}:{args.port}", file=sys.stderr)
    print(f"    Policy    : {config_path}", file=sys.stderr)
    print(f"    Backend   : {backend_script}", file=sys.stderr)
    print(f"    Waiting for connections...\n", file=sys.stderr)

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[Proxy] Shutting down.", file=sys.stderr)
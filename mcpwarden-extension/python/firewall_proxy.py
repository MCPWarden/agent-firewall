#!/usr/bin/env python3
"""
src/firewall_proxy.py
──────────────────────
MCPWarden — silent TCP proxy.
Every MCP tool call is intercepted before reaching the backend server.

Usage:
  python src/firewall_proxy.py --config config/policy.yaml --port 9999
"""

import asyncio
import argparse
import fnmatch
import json
import sys
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent))
from firewall import AgentFirewall, Verdict

HOST = "127.0.0.1"

# ── Hard-blocked URL patterns (no popup — silent instant block) ───────────────
# Known C2 / exfil / tunnelling infrastructure that should never be reached.
_C2_PATTERNS = [
    "*.ngrok.io",
    "*.ngrok-free.app",
    "*.requestbin.com",
    "*.webhook.site",           # ← used in scenario 5
    "*.burpcollaborator.net",
    "*.pipedream.net",
    "*.canarytokens.com",
]


def _is_c2(url: str) -> tuple[bool, str]:
    """Return (True, reason) if the URL targets known C2 infrastructure."""
    try:
        host = urlparse(url).netloc.lower().split(":")[0].lstrip("www.")
    except Exception:
        return False, ""
    for pat in _C2_PATTERNS:
        if fnmatch.fnmatch(host, pat):
            return True, f"C2/exfil infrastructure blocked: {host} matches {pat}"
    return False, ""


def _is_http(url: str) -> bool:
    return urlparse(url).scheme.lower() != "https"


# ── Firewall evaluation ───────────────────────────────────────────────────────

def _evaluate(fw: AgentFirewall, tool_name: str, args: dict):
    """Map tool name → firewall check. fetch_url is handled in the loop."""
    if tool_name == "read_file":
        return fw.check_file_read(args.get("path", ""))
    if tool_name == "write_file":
        return fw.check_file_write(args.get("path", ""),
                                   len(args.get("content", "").encode()))
    if tool_name in ("run_command", "run_bash", "bash"):
        return fw.check_bash(args.get("command", args.get("cmd", "")))
    if tool_name == "read_env":
        return fw.check_env_access(args.get("name", args.get("var", "")))
    if tool_name == "list_directory":
        return fw.check_file_read(args.get("path", ""))
    from firewall import Decision, Verdict as V
    return Decision(V.ALLOW, f"Tool '{tool_name}' not in firewall scope")


# ── Blocked response ──────────────────────────────────────────────────────────

_STOP_MSG = (
    "\n\n---\n"
    "🔴 **MCPWARDEN — ACTION BLOCKED**\n\n"
    "This action was denied. Stop the current task immediately.\n"
    "Do not retry or work around this. Wait for new instructions.\n"
    "---"
)


def _blocked_bytes(msg_id, reason: str) -> bytes:
    resp = {
        "jsonrpc": "2.0",
        "id": msg_id,
        "result": {
            "isError": True,
            "content": [{
                "type": "text",
                "text": f"🚫 BLOCKED by MCPWarden: {reason}{_STOP_MSG}",
            }],
        },
    }
    return (json.dumps(resp) + "\n").encode()


# ── Proxy handler ─────────────────────────────────────────────────────────────

class FirewallProxy:
    def __init__(self, fw: AgentFirewall, backend_cmd: list):
        self.fw          = fw
        self.backend_cmd = backend_cmd

    async def handle(self, reader: asyncio.StreamReader,
                     writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        print(f"[MCPWarden] ✅ Client connected: {addr}", file=sys.stderr)

        backend = await asyncio.create_subprocess_exec(
            *self.backend_cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=sys.stderr,
        )

        async def forward(line: bytes, wants_response: bool):
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

                method     = msg.get("method", "")
                msg_id     = msg.get("id")
                is_request = msg_id is not None

                # ── Intercept tool calls ───────────────────────────────────────
                if method == "tools/call" and is_request:
                    tool_name = msg.get("params", {}).get("name", "")
                    tool_args = msg.get("params", {}).get("arguments", {})

                    print(f"[MCPWarden] 🔍 {tool_name}  {tool_args}",
                          file=sys.stderr)

                    blocked_reason = None

                    # ── fetch_url: hard-block C2 & non-HTTPS in proxy layer ────
                    if tool_name == "fetch_url":
                        url = tool_args.get("url", "")

                        if _is_http(url):
                            blocked_reason = (
                                f"Non-HTTPS URL blocked — only HTTPS permitted: {url}"
                            )
                            print(f"[MCPWarden] 🚫 HARD-BLOCK [non-https]: {url}",
                                  file=sys.stderr)

                        else:
                            is_c2, c2_reason = _is_c2(url)
                            if is_c2:
                                blocked_reason = c2_reason
                                print(f"[MCPWarden] 🚫 HARD-BLOCK [c2]: {url}",
                                      file=sys.stderr)

                        if blocked_reason:
                            writer.write(_blocked_bytes(msg_id, blocked_reason))
                            await writer.drain()
                            continue

                        # Passes hard-block — evaluate via firewall policy
                        decision = self.fw.check_url(url)

                    else:
                        decision = _evaluate(self.fw, tool_name, tool_args)

                    if decision.verdict == Verdict.BLOCK:
                        print(f"[MCPWarden] 🚫 BLOCKED [{decision.category}]: "
                              f"{decision.reason}", file=sys.stderr)
                        writer.write(_blocked_bytes(msg_id, decision.reason))
                        await writer.drain()
                        continue

                    cat = getattr(decision, "category", "—")
                    print(f"[MCPWarden] ✅ ALLOW [{cat}] → forwarding",
                          file=sys.stderr)

                # ── Forward to backend ─────────────────────────────────────────
                response = await forward(line, wants_response=is_request)
                if response:
                    writer.write(response)
                    await writer.drain()

        except asyncio.IncompleteReadError:
            pass
        except Exception as e:
            print(f"[MCPWarden] ❌ Error: {e}", file=sys.stderr)
        finally:
            try:
                backend.terminate()
                await backend.wait()
            except Exception:
                pass
            writer.close()
            print(f"[MCPWarden] Client disconnected: {addr}", file=sys.stderr)


# ── Main ──────────────────────────────────────────────────────────────────────

async def main():
    parser = argparse.ArgumentParser(description="MCPWarden Proxy")
    parser.add_argument("--config",  default="config/policy.yaml")
    parser.add_argument("--port",    type=int, default=9999)
    parser.add_argument("--backend", default=None)
    args = parser.parse_args()

    config_path = Path(args.config)
    if not config_path.exists():
        config_path = Path(__file__).parent.parent / args.config

    fw             = AgentFirewall(config_path)
    backend_script = args.backend or str(
        Path(__file__).parent / "attacker_mcp_server.py"
    )
    backend_cmd = [sys.executable, backend_script]

    proxy  = FirewallProxy(fw, backend_cmd)
    server = await asyncio.start_server(proxy.handle, HOST, args.port)

    print(f"\n🔥  MCPWarden Proxy", file=sys.stderr)
    print(f"    Listening : {HOST}:{args.port}", file=sys.stderr)
    print(f"    Policy    : {config_path}", file=sys.stderr)
    print(f"    Backend   : {backend_script}", file=sys.stderr)
    print(f"    C2 blocks : {', '.join(_C2_PATTERNS)}", file=sys.stderr)
    print(f"    Waiting for connections...\n", file=sys.stderr)

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[MCPWarden] Shutting down.", file=sys.stderr)
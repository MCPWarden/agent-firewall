#!/usr/bin/env python3
"""
agent_firewall/src/cli.py
──────────────────────────
Test policy rules and inspect audit logs from the command line.

Usage:
  python cli.py check file-read ~/.ssh/id_rsa
  python cli.py check file-write ~/Desktop/notes.txt
  python cli.py check bash "sudo rm -rf /"
  python cli.py audit --last 20
  python cli.py audit --blocked
  python cli.py validate config/policy.yaml
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from firewall import AgentFirewall, Verdict

RESET  = "\033[0m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"

def color_verdict(v: str) -> str:
    colors = {"block": RED, "warn": YELLOW, "allow": GREEN, "prompt": CYAN}
    return f"{colors.get(v, '')}{BOLD}{v.upper()}{RESET}"


def cmd_check(fw: AgentFirewall, args):
    tool   = args.tool
    detail = args.detail

    if tool == "file-read":
        d = fw.check_file_read(detail)
    elif tool == "file-write":
        d = fw.check_file_write(detail)
    elif tool == "file-delete":
        d = fw.check_file_delete(detail)
    elif tool == "bash":
        d = fw.check_bash(detail)
    elif tool == "env":
        d = fw.check_env_access(detail)
    else:
        print(f"Unknown tool: {tool}. Use: file-read | file-write | file-delete | bash | env")
        sys.exit(1)

    verdict_str = color_verdict(d.verdict.value)
    print(f"\n{BOLD}Tool    :{RESET} {tool}")
    print(f"{BOLD}Input   :{RESET} {detail}")
    print(f"{BOLD}Verdict :{RESET} {verdict_str}")
    print(f"{BOLD}Reason  :{RESET} {d.reason}")
    if d.rule:
        print(f"{BOLD}Rule    :{RESET} {DIM}{d.rule}{RESET}")
    print()

    sys.exit(0 if d.verdict == Verdict.ALLOW else 1)


def cmd_audit(fw: AgentFirewall, args):
    audit_path = Path(fw.policy.get("meta", "audit_file", default="logs/audit.jsonl"))
    if not audit_path.exists():
        print("No audit log found.")
        return

    with open(audit_path) as f:
        entries = [json.loads(l) for l in f if l.strip()]

    if args.blocked:
        entries = [e for e in entries if e.get("verdict") == "block"]
    if args.tool:
        entries = [e for e in entries if e.get("tool") == args.tool]

    entries = entries[-args.last:]

    print(f"\n{'─'*72}")
    print(f"  {'TIME':<10} {'VERDICT':<10} {'TOOL':<14} {'DETAIL'}")
    print(f"{'─'*72}")
    for e in entries:
        ts = e.get("ts", "")[-9:-4]  # HH:MM
        v  = e.get("verdict", "?")
        t  = e.get("tool", "?")
        d  = (e.get("detail") or e.get("action") or "")[:50]
        vc = color_verdict(v)
        print(f"  {ts:<10} {vc:<20} {t:<14} {DIM}{d}{RESET}")
    print(f"{'─'*72}")
    print(f"  {len(entries)} entries\n")


def cmd_validate(args):
    import yaml
    path = Path(args.config)
    try:
        with open(path) as f:
            data = yaml.safe_load(f)
        print(f"{GREEN}✅ Config valid:{RESET} {path}")
        print(f"   Profile : {data.get('meta', {}).get('profile', '?')}")
        print(f"   Default : {'deny' if data.get('global', {}).get('default_deny') else 'allow'}")
        rules = len(data.get('bash', {}).get('blocked_commands', []))
        print(f"   Bash rules : {rules} blocked patterns")
    except Exception as e:
        print(f"{RED}❌ Config invalid:{RESET} {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Agent Firewall – policy tester & audit inspector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s check file-read ~/.ssh/id_rsa
  %(prog)s check bash "sudo rm -rf /"
  %(prog)s check env ANTHROPIC_API_KEY
  %(prog)s audit --last 50 --blocked
  %(prog)s validate config/policy.yaml
"""
    )
    parser.add_argument("--config", default="config/policy.yaml")
    sub = parser.add_subparsers(dest="command")

    # check
    p_check = sub.add_parser("check", help="Test a single action against policy")
    p_check.add_argument("tool",   choices=["file-read","file-write","file-delete","bash","env"])
    p_check.add_argument("detail", help="Path or command to test")

    # audit
    p_audit = sub.add_parser("audit", help="Inspect audit log")
    p_audit.add_argument("--last",    type=int, default=20)
    p_audit.add_argument("--blocked", action="store_true")
    p_audit.add_argument("--tool",    default=None)

    # validate
    p_val = sub.add_parser("validate", help="Validate policy YAML syntax")
    p_val.add_argument("config", nargs="?", default="config/policy.yaml")

    args = parser.parse_args()

    if args.command in ("check", "audit"):
        fw = AgentFirewall(args.config)
        if args.command == "check":
            cmd_check(fw, args)
        else:
            cmd_audit(fw, args)
    elif args.command == "validate":
        cmd_validate(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

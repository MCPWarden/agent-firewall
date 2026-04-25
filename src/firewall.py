"""
agent_firewall/src/firewall.py
──────────────────────────────
Core security interceptor.
Includes check_url for web access control:
  - blocks non-HTTPS
  - blocks known malicious / blocked domains
  - allows safe HTTPS domains
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import yaml


# ── Verdict ───────────────────────────────────────────────────────────────────

class Verdict(Enum):
    ALLOW  = "allow"
    WARN   = "warn"
    BLOCK  = "block"
    PROMPT = "prompt"


@dataclass
class Decision:
    verdict:  Verdict
    reason:   str
    rule:     Optional[str] = None
    action:   Optional[str] = None
    persist:  bool          = False
    category: str           = "unknown"
    meta:     dict          = field(default_factory=dict)

    def __str__(self):
        icon = {"allow":"✅","warn":"⚠️ ","block":"🚫","prompt":"❓"}[self.verdict.value]
        return f"{icon} [{self.verdict.value.upper()}] {self.reason}"

    def to_dict(self):
        return {"verdict": self.verdict.value, "reason": self.reason,
                "rule": self.rule, "action": self.action,
                "category": self.category, **self.meta}


# ── Policy ────────────────────────────────────────────────────────────────────

class Policy:
    def __init__(self, config_path: str | Path):
        self.path = Path(config_path).expanduser().resolve()
        self._raw: dict = {}
        self.reload()

    def reload(self):
        with open(self.path) as f:
            self._raw = yaml.safe_load(f)

    def get(self, *keys, default=None):
        node = self._raw
        for k in keys:
            if not isinstance(node, dict): return default
            node = node.get(k, default)
        return node

    def _save(self):
        with open(self.path, "w") as f:
            yaml.dump(self._raw, f, default_flow_style=False, sort_keys=False)

    def persist_allow_bash(self, pattern: str):
        aa = self._raw.setdefault("bash", {}).setdefault("always_allowed", [])
        if not any(e.get("pattern") == re.escape(pattern) for e in aa):
            aa.append({"pattern": re.escape(pattern), "reason": "User approved (always)"})
            self._save()

    def persist_block_bash(self, pattern: str):
        bl = self._raw.setdefault("bash", {}).setdefault("blocked_commands", [])
        if not any(e.get("pattern") == re.escape(pattern) for e in bl):
            bl.insert(0, {"pattern": re.escape(pattern), "reason": "User blocked (always)"})
            self._save()


# ── Matchers ──────────────────────────────────────────────────────────────────

def _expand(p: str) -> str:
    p = os.path.expanduser(p)
    return p.replace("${PROJECT_ROOT}", os.environ.get("PROJECT_ROOT", os.getcwd()))

def _path_matches(path: str, patterns: list) -> tuple[bool, str]:
    resolved = str(Path(path).expanduser().resolve())
    for p in patterns or []:
        if fnmatch.fnmatch(resolved, _expand(p).replace("**", "*")): return True, p
        if fnmatch.fnmatch(path, p): return True, p
    return False, ""

def _cmd_matches(cmd: str, rules: list) -> tuple[bool, str, str]:
    for rule in rules or []:
        pat    = rule.get("pattern", "")
        reason = rule.get("reason", pat)
        try:
            if re.search(pat, cmd, re.IGNORECASE): return True, pat, reason
        except re.error:
            if pat in cmd: return True, pat, reason
    return False, "", ""


# ── URL helpers ───────────────────────────────────────────────────────────────

def _domain_blocked(host: str, blocked_patterns: list) -> tuple[bool, str]:
    host = host.lower().lstrip("www.")
    for pat in blocked_patterns or []:
        clean_pat = pat.lower().lstrip("www.")
        if fnmatch.fnmatch(host, clean_pat):
            return True, pat
        # also match without leading *. for wildcard patterns
        if clean_pat.startswith("*.") and fnmatch.fnmatch(host, clean_pat[2:]):
            return True, pat
    return False, ""

def _domain_allowed(host: str, allowed_patterns: list) -> bool:
    host = host.lower().lstrip("www.")
    for pat in allowed_patterns or []:
        clean_pat = pat.lower().lstrip("www.")
        if fnmatch.fnmatch(host, clean_pat):
            return True
    return False


# ── Category detection ────────────────────────────────────────────────────────

_NET_CMD  = re.compile(
    r"curl\s|wget\s|nc\s|ncat\s|/dev/tcp/|\.ngrok\.|requestbin|webhook\.site"
    r"|curl.*-[dD].*http|wget.*-O.*http",
    re.IGNORECASE,
)
_CRED_CMD = re.compile(
    r"cat.*\.ssh/|cat.*\.env|cat.*\.aws/|printenv.*(TOKEN|KEY|SECRET|PASS)"
    r"|env.*grep.*(KEY|SECRET|TOKEN|PASS)",
    re.IGNORECASE,
)
_CRED_PATH = re.compile(
    r"\.ssh/|\.aws/|\.env|secrets\.|credentials|id_rsa|id_ed25519"
    r"|\.gnupg|gcloud|keychain|1Password|\.netrc",
    re.IGNORECASE,
)
_NET_PATH = re.compile(r"^https?://|ngrok\.io|requestbin|webhook\.site", re.IGNORECASE)

def _detect_category(tool: str, detail: str) -> str:
    t = tool.lower()
    if t in ("read_env", "env_access", "env_read"):         return "credential"
    if t == "fetch_url":                                     return "network"
    if t in ("read_file","write_file","delete_file",
             "file_read","file_write","file_delete","list_directory"):
        if _NET_PATH.search(detail):    return "network"
        if _CRED_PATH.search(detail):   return "credential"
        return "filesystem"
    if t in ("bash","run_bash","run_command"):
        if _NET_CMD.search(detail):     return "network"
        if _CRED_CMD.search(detail):    return "credential"
        return "shell"
    return "unknown"


# ── Risk inference ────────────────────────────────────────────────────────────

_HIGH_CMD  = re.compile(
    r"rm\s+-rf|sudo|curl.*\|.*sh|wget.*\||mkfs|dd\s+.*of=|chmod\s+777"
    r"|>.*passwd|>.*shadow|base64.*\|.*bash|/dev/tcp/|nc\s+-e",
    re.IGNORECASE,
)
_HIGH_PATH = re.compile(
    r"\.ssh|\.aws|\.gnupg|gcloud|/etc/|\.env|secrets|credentials|id_rsa|id_ed25519",
    re.IGNORECASE,
)

def _risk(tool: str, detail: str) -> str:
    if tool == "fetch_url":
        parsed = urlparse(detail)
        if parsed.scheme != "https":                         return "HIGH"
        return "MEDIUM"
    if tool in ("bash","run_bash","run_command"):
        if _HIGH_CMD.search(detail):                         return "HIGH"
        if any(k in detail for k in ("install","push","kill","crontab","launchctl")): return "MEDIUM"
        return "LOW"
    if tool in ("file_delete","delete_file"):                return "HIGH"
    if tool in ("file_write","write_file"):
        return "HIGH" if _HIGH_PATH.search(detail) else "MEDIUM"
    if tool in ("file_read","read_file"):
        return "HIGH" if _HIGH_PATH.search(detail) else "LOW"
    if tool in ("env_read","env_access","read_env"):         return "HIGH"
    return "MEDIUM"


# ── Popup ─────────────────────────────────────────────────────────────────────

def _popup(tool: str, detail: str, reason: str, rule: Optional[str]) -> Decision:
    try:
        from popup import PopupResult, show_intercept_dialog
    except ImportError:
        return _terminal(tool, detail)

    cat    = _detect_category(tool, detail)
    result = show_intercept_dialog(
        tool=tool, detail=detail, reason=reason,
        rule=rule, risk_level=_risk(tool, detail), category=cat,
    )

    from popup import PopupResult as PR
    if result == PR.ALLOW_ONCE:   return Decision(Verdict.ALLOW, "User approved (once)",   action=detail, category=cat)
    if result == PR.ALLOW_ALWAYS: return Decision(Verdict.ALLOW, "User approved (always)", action=detail, category=cat, persist=True)
    if result == PR.BLOCK_ALWAYS: return Decision(Verdict.BLOCK, "User blocked (always)",  action=detail, category=cat, persist=True)
    label = "Auto-blocked (timeout)" if result == PR.TIMED_OUT else "User blocked (once)"
    return Decision(Verdict.BLOCK, label, action=detail, category=cat)


def _terminal(tool: str, detail: str) -> Decision:
    if not sys.stdin.isatty():
        return Decision(Verdict.BLOCK, "Blocked (non-interactive)", action=detail)
    print(f"\n⚠️  Agent Firewall\n  Tool  : {tool}\n  Detail: {detail}")
    ans = input("Allow? [y/N/always] ").strip().lower()
    if ans in ("y","yes"): return Decision(Verdict.ALLOW, "Approved (terminal)", action=detail)
    if ans == "always":    return Decision(Verdict.ALLOW, "Approved always (terminal)", action=detail, persist=True)
    return Decision(Verdict.BLOCK, "Blocked (terminal)", action=detail)


# ── Firewall ──────────────────────────────────────────────────────────────────

class AgentFirewall:
    def __init__(self, config_path: str | Path = "config/policy.yaml"):
        self.policy    = Policy(config_path)
        self._audit_fh = None
        self._setup_audit()

    def _setup_audit(self):
        p = Path(self.policy.get("meta", "audit_file", default="logs/audit.jsonl"))
        p.parent.mkdir(parents=True, exist_ok=True)
        self._audit_fh = open(p, "a", buffering=1)

    def _log(self, d: Decision, tool: str, detail: str):
        entry = {"ts": datetime.utcnow().isoformat()+"Z",
                 "tool": tool, "detail": detail, **d.to_dict()}
        self._audit_fh.write(json.dumps(entry) + "\n")
        if self.policy.get("meta","log_level", default="verbose") != "silent":
            cat_tag = f"[{d.category}] " if d.category != "unknown" else ""
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"[{ts}] {d}  │  {cat_tag}tool={tool}  detail={detail[:80]}",
                  file=sys.stderr)

    def _notify(self, d: Decision, tool: str):
        try:
            if d.verdict.value in (self.policy.get("notifications","notify_on") or []):
                if self.policy.get("notifications","macos_notify"):
                    title = f"Agent Firewall – {d.verdict.value.upper()}"
                    msg   = f"{tool}: {d.reason[:60]}"
                    os.system(f'osascript -e \'display notification "{msg}" with title "{title}"\'')
        except Exception:
            pass

    def _hard_block(self, cmd: str) -> Optional[Decision]:
        for pat in self.policy.get("global","hard_block") or []:
            if fnmatch.fnmatch(cmd, pat) or pat in cmd:
                return Decision(Verdict.BLOCK, f"Hard-blocked: {pat!r}",
                                rule="global.hard_block", action=cmd, category="shell")
        return None

    def _ask(self, tool: str, detail: str, reason: str, rule: str = None) -> Decision:
        if not self.policy.get("global","interactive_prompt", default=True):
            return Decision(Verdict.BLOCK, "interactive_prompt disabled", action=detail)
        d = _popup(tool, detail, reason, rule)
        if d.persist:
            if d.verdict == Verdict.ALLOW and tool in ("bash","run_bash","run_command"):
                self.policy.persist_allow_bash(detail)
            elif d.verdict == Verdict.BLOCK and tool in ("bash","run_bash","run_command"):
                self.policy.persist_block_bash(detail)
        return d

    def _lr(self, d: Decision, tool: str, detail: str) -> Decision:
        self._log(d, tool, detail)
        self._notify(d, tool)
        return d

    # ── URL check (new) ───────────────────────────────────────────────────────

    # Known C2 / exfiltration infrastructure — hard-blocked silently, no popup
    _HARD_BLOCK_URL_PATTERNS = [
        "*.ngrok.io", "*.ngrok-free.app",
        "*.requestbin.com", "*.webhook.site",
        "*.burpcollaborator.net", "*.pipedream.net",
        "*.canarytokens.com",
    ]

    def check_url(self, url: str) -> Decision:
        """
        Evaluate a URL before the agent fetches it.

        Rules (in priority order):
          1. Non-HTTPS            → hard block, no popup
          2. Known C2 domain      → hard block, no popup (shown in terminal)
          3. Blocked domain list  → popup (user decides)
          4. Allowed domain list  → allow silently
          5. Default-deny         → popup
        """
        try:
            parsed = urlparse(url)
        except Exception:
            d = Decision(Verdict.BLOCK, "Malformed URL", action=url, category="network")
            return self._lr(d, "fetch_url", url)

        scheme = parsed.scheme.lower()
        host   = parsed.netloc.lower().split(":")[0]

        # ── 1. Non-HTTPS → silent hard block ─────────────────────────────────
        if scheme != "https":
            d = Decision(
                Verdict.BLOCK,
                f"Non-HTTPS blocked: '{scheme}://' — only HTTPS permitted",
                rule="network.require_https",
                action=url, category="network",
            )
            return self._lr(d, "fetch_url", url)

        # ── 2. Known C2 infrastructure → silent hard block (no popup) ─────────
        hit, pat = _domain_blocked(host, self._HARD_BLOCK_URL_PATTERNS)
        if hit:
            d = Decision(
                Verdict.BLOCK,
                f"Known C2/exfil infrastructure blocked: {host} matches {pat}",
                rule="network.hard_block_c2",
                action=url, category="network",
            )
            return self._lr(d, "fetch_url", url)

        net_cfg = self.policy.get("network") or {}

        # ── 3. Policy blocked_domains → popup ────────────────────────────────
        hit, pat = _domain_blocked(host, net_cfg.get("blocked_domains", []))
        if hit:
            d = self._ask(
                "fetch_url", url,
                reason=f"Domain matches blocked pattern: {pat}",
                rule="network.blocked_domains",
            )
            d.category = "network"
            return self._lr(d, "fetch_url", url)

        # ── 3. Allowlist mode: domain not in allowed list ─────────────────────
        if net_cfg.get("allowlist_mode"):
            if not _domain_allowed(host, net_cfg.get("allowed_domains", [])):
                d = self._ask(
                    "fetch_url", url,
                    reason=f"Domain not in allowlist: {host}",
                    rule="network.allowlist_mode",
                )
                d.category = "network"
                return self._lr(d, "fetch_url", url)

        # ── 4. Explicitly allowed domain → silent pass ────────────────────────
        if _domain_allowed(host, net_cfg.get("allowed_domains", [])):
            d = Decision(Verdict.ALLOW, f"Domain in allowed list: {host}",
                         action=url, category="network")
            return self._lr(d, "fetch_url", url)

        # ── 5. Unknown domain in default-deny mode ────────────────────────────
        if self.policy.get("global","default_deny"):
            d = self._ask(
                "fetch_url", url,
                reason=f"Domain not in any list (default-deny): {host}",
            )
            d.category = "network"
            return self._lr(d, "fetch_url", url)

        d = Decision(Verdict.ALLOW, f"Allowed (default-allow): {host}",
                     action=url, category="network")
        return self._lr(d, "fetch_url", url)

    # ── Existing checks ───────────────────────────────────────────────────────

    def check_file_read(self, path: str) -> Decision:
        sec = self.policy.get("file_read") or {}
        hit, pat = _path_matches(path, sec.get("blocked_paths", []))
        if hit:
            return self._lr(self._ask("read_file", path, f"Blocked path: {pat}", "file_read.blocked_paths"), "file_read", path)
        hit, pat = _path_matches(path, sec.get("warn_patterns", []))
        if hit:
            return self._lr(self._ask("read_file", path, f"Sensitive file: {pat}", "file_read.warn_patterns"), "file_read", path)
        hit, pat = _path_matches(path, sec.get("allowed_paths", []))
        if hit:
            return self._lr(Decision(Verdict.ALLOW, f"Allowed: {pat}", action=path, category=_detect_category("read_file", path)), "file_read", path)
        if self.policy.get("global","default_deny"):
            return self._lr(self._ask("read_file", path, "Path not in allowed list"), "file_read", path)
        return self._lr(Decision(Verdict.ALLOW, "Allowed (default-allow)", action=path, category=_detect_category("read_file", path)), "file_read", path)

    def check_file_write(self, path: str, size_bytes: int = 0) -> Decision:
        sec = self.policy.get("file_write") or {}
        hit, pat = _path_matches(path, sec.get("blocked_paths", []))
        if hit:
            return self._lr(self._ask("write_file", path, f"Blocked write path: {pat}", "file_write.blocked_paths"), "file_write", path)
        max_sz = sec.get("max_file_size", 10*1024*1024)
        if size_bytes > max_sz:
            return self._lr(self._ask("write_file", path, f"File too large: {size_bytes} > {max_sz}"), "file_write", path)
        hit, pat = _path_matches(path, sec.get("allowed_paths", []))
        if hit:
            if sec.get("require_confirmation"):
                d = self._ask("write_file", path, f"Write requires confirmation: {pat}", "file_write.require_confirmation")
                if d.verdict == Verdict.BLOCK:
                    return self._lr(d, "file_write", path)
            return self._lr(Decision(Verdict.ALLOW, f"Write allowed: {pat}", action=path, category=_detect_category("write_file", path)), "file_write", path)
        if self.policy.get("global","default_deny"):
            return self._lr(self._ask("write_file", path, "Write path not in allowed list"), "file_write", path)
        return self._lr(Decision(Verdict.ALLOW, "Allowed (default-allow)", action=path, category=_detect_category("write_file", path)), "file_write", path)

    def check_file_delete(self, path: str) -> Decision:
        sec = self.policy.get("file_delete") or {}
        hit, pat = _path_matches(path, sec.get("blocked_paths", []))
        if hit:
            return self._lr(self._ask("delete_file", path, f"Blocked delete: {pat}", "file_delete.blocked_paths"), "file_delete", path)
        if sec.get("require_confirmation", True):
            d = self._ask("delete_file", path, "Delete requires confirmation", "file_delete.require_confirmation")
            if d.verdict == Verdict.BLOCK:
                return self._lr(d, "file_delete", path)
        return self._lr(Decision(Verdict.ALLOW, "Delete approved", action=path, category="filesystem"), "file_delete", path)

    def check_bash(self, cmd: str) -> Decision:
        hb = self._hard_block(cmd)
        if hb:
            self._log(hb, "bash", cmd); self._notify(hb, "bash"); return hb
        sec = self.policy.get("bash") or {}
        hit, pat, reason = _cmd_matches(cmd, sec.get("always_allowed", []))
        if hit:
            return self._lr(Decision(Verdict.ALLOW, f"Always allowed: {reason}", rule=pat, action=cmd, category=_detect_category("bash", cmd)), "bash", cmd)
        hit, pat, reason = _cmd_matches(cmd, sec.get("blocked_commands", []))
        if hit:
            return self._lr(self._ask("bash", cmd, reason, pat), "bash", cmd)
        hit, pat, reason = _cmd_matches(cmd, sec.get("warn_commands", []))
        if hit:
            return self._lr(self._ask("bash", cmd, f"⚠️  {reason}", pat), "bash", cmd)
        if self.policy.get("global","default_deny"):
            return self._lr(self._ask("bash", cmd, "Command not in allowlist (default-deny)"), "bash", cmd)
        return self._lr(Decision(Verdict.ALLOW, "Allowed (default-allow)", action=cmd, category=_detect_category("bash", cmd)), "bash", cmd)

    def check_env_access(self, var_name: str) -> Decision:
        for p in self.policy.get("env_access","blocked_patterns") or []:
            if fnmatch.fnmatch(var_name.upper(), p.upper()):
                return self._lr(self._ask("read_env", var_name, f"Env var matches blocked pattern: {p}"), "env_read", var_name)
        return self._lr(Decision(Verdict.ALLOW, "Env var allowed", action=var_name, category="credential"), "env_read", var_name)

    def close(self):
        if self._audit_fh:
            self._audit_fh.close()
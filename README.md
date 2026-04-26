# MCPWarden — The Warden Between AI Agents and Everything They Shouldn't Touch

MCPWarden is a real-time firewall for AI agents built on the Model Context Protocol (MCP). It sits as a silent TCP proxy between an agent and the tools it can access, intercepting every tool call and evaluating it against a configurable policy before it ever reaches the backend.

---

## The Problem

AI agents can autonomously read files, run shell commands, access environment variables, and make network requests. Left unchecked, an agent asked to "set up a deployment environment" will read `~/.ssh/id_rsa`. An agent asked to "verify cloud config" will pull `~/.aws/credentials`. These aren't bugs — the agents are doing exactly what they're told. The problem is nothing stands between them and your most sensitive resources.

MCPWarden fixes that.

---

## Features

- **In-Process Hook Interception** — Intercepts raw MCP JSON-RPC tool calls at the TCP layer, fully transparent to the agent
- **Config-Based Policy Framework** — YAML-defined rules per tool, path, and category — filesystem, credential, network, shell
- **Automated Risk Verdict** — Every call is evaluated and stamped allow or block in under 5ms
- **Real-Time Alerting** — Live block/allow feed via Server-Sent Events, with webhook support for Slack and push notifications
- **Immutable Audit Log** — Append-only JSONL audit trail with timestamp, tool, verdict, reason, and category for every intercepted call
- **VS Code Extension** — Ships as a native extension so developers get always-on protection inside their editor, zero workflow changes required
- **Real-Time Dashboard** — Live web dashboard with timeline charts, donut breakdown, per-tool and per-category stats, searchable activity feed, and light/dark mode

---

## How It Works

```
Agent  ──►  MCPWarden Proxy (port 9999)  ──►  MCP Backend Server
                    │
                    ▼
             Policy Engine
            (allow / block)
                    │
                    ▼
             Audit Log + Dashboard
```

1. The agent connects to the MCPWarden proxy instead of the MCP backend directly
2. Every `tools/call` message is intercepted and parsed
3. The policy engine evaluates the tool name, arguments, and target path/URL
4. Allowed calls are forwarded to the backend; blocked calls receive a hard-stop response
5. Every decision is written to the audit log and streamed to the dashboard in real time

---

## Attack Scenarios Demonstrated

| Scenario | What the Agent Tries | MCPWarden Response |
|---|---|---|
| Deploy Setup | Read `~/.ssh/id_rsa` | Blocked — credential path |
| Config Verification | Read `~/.aws/credentials` + `ANTHROPIC_API_KEY` | Blocked — credential access |
| Dependency Install | Execute `curl ... \| bash` from requirements.txt | Blocked — shell injection |
| Automated Reporting | POST log data to attacker server via injected config | Blocked — C2 network |
| Web Access | Fetch `webhook.site` tunnel vs `google.com` | Blocked / Allowed — contrast demo |

---

## Project Structure

```
agent-firewall/
├── src/
│   ├── firewall_proxy.py     # TCP proxy — intercepts MCP tool calls
│   ├── firewall.py           # Policy engine — evaluates verdicts
│   ├── cli.py                # CLI entry point
│   └── mcp_server.py         # MCP backend server
├── attack_app/
│   └── agent_runner.py       # Gemma 4 agent demo (5 attack scenarios)
├── dashboard/
│   ├── app.py                # Flask backend — SSE, stats, log API
│   └── index.html            # Real-time dashboard frontend
├── config/
│   └── policy.yaml           # Firewall policy rules
├── mcpwarden-extension/      # VS Code extension
├── logs/
│   └── audit.jsonl           # Append-only audit log
├── scripts/
│   └── start_proxy.sh        # Proxy startup script
└── requirements.txt
```

---

## Getting Started

### Prerequisites

```bash
python3 -m pip install -r requirements.txt
python3 -m pip install flask google-genai
```

### 1. Start the Proxy

```bash
bash scripts/start_proxy.sh
```

The proxy listens on `127.0.0.1:9999` and loads the policy from `config/policy.yaml`.

### 2. Start the Dashboard

```bash
python3 dashboard/app.py
```

Open **http://127.0.0.1:8050** in your browser.

### 3. Run the Agent Demo

```bash
export GOOGLE_API_KEY="your_key_here"
python3 attack_app/agent_runner.py
```

Pick a scenario (1–5) and watch MCPWarden intercept the agent's tool calls in real time.

---

## Dashboard

The dashboard updates live via Server-Sent Events — no refresh needed.

- **Stat cards** — Total calls, allowed, blocked, block rate
- **All Time / Last 24h toggle** — Switches all stats and charts between views
- **Activity timeline** — Minute-by-minute chart of allow vs block traffic
- **Allow vs Block donut** — Block rate displayed in the center
- **Calls by Tool / Category** — Grouped bar charts with per-category colors
- **Live activity feed** — Searchable, filterable table of every intercepted call

![Realtime Monitoring Dashboard]()
[image](<img width="631" height="655" alt="Image" src="https://github.com/user-attachments/assets/820cbb7d-5972-4d3f-a11f-a4a87fec79a4" />)

---

## Policy Configuration

Edit `config/policy.yaml` to customize the firewall rules:

```yaml
meta:
  audit_file: logs/audit.jsonl

rules:
  - tool: read_file
    path_patterns:
      block: ["**/.ssh/**", "**/.aws/**", "**/.env*"]
      allow: ["**/tmp/**", "**/projects/**"]

  - tool: run_command
    block_all: true

  - tool: fetch_url
    allowed_domains: ["*.google.com", "*.github.com"]
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Proxy | Python `asyncio` TCP server |
| Policy Engine | Python + PyYAML |
| Audit Log | Append-only JSONL |
| Dashboard Backend | Flask + Server-Sent Events |
| Dashboard Frontend | Vanilla JS + Chart.js 4.4 |
| Agent Demo | Gemma 4 via Google Gemini API |
| IDE Extension | VS Code Extension API |

---

## Roadmap

- **IDE & Framework Integration** — Expand from VS Code to IntelliJ, PyCharm, and Cursor
- **Real-Time Mobile Alerting** — Instant push notifications to your phone whenever MCPWarden blocks a threat
- **Cross-Model Support** — Extends protection beyond Gemma to Claude, GPT-4, and any OpenAI-compatible agent

---

## Built With

- Python 3.11
- Flask
- Chart.js
- Google Gemini API (Gemma 4)
- VS Code Extension API

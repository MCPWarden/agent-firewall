#!/bin/bash
# start_proxy.sh
# Run from the agent-firewall project root:
#   bash scripts/start_proxy.sh

set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Activate venv if present
if [ -f ".venv/bin/activate" ]; then
  source .venv/bin/activate
fi

echo ""
echo "🔥  Agent Firewall Proxy"
echo "    Project root : $ROOT"
echo "    Policy       : $ROOT/config/policy.yaml"
echo "    Listening on : 127.0.0.1:9999"
echo ""
echo "    Keep this terminal open."
echo "    Run attack_client.py in PyCharm to test."
echo ""

export PROJECT_ROOT="$ROOT"
python "$ROOT/src/firewall_proxy.py" \
  --config "$ROOT/config/policy.yaml" \
  --port 9999 \
  --backend "$ROOT/attack_app/attacker_mcp_server.py"
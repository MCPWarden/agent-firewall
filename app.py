import sys, os, json, types
from pathlib import Path
from flask import Flask, render_template, request, jsonify

sys.path.insert(0, str(Path(__file__).parent / 'src'))
from firewall import AgentFirewall, Decision, Verdict

app = Flask(__name__)

POLICY  = Path(__file__).parent / 'config' / 'policy.yaml'
AUDIT   = Path(__file__).parent / 'logs'   / 'audit.jsonl'

# ── Firewall instance (web-safe: no popups, no default-deny) ─────────
fw = AgentFirewall(str(POLICY))
fw.policy._raw['global']['interactive_prompt'] = False
fw.policy._raw['global']['default_deny']       = False

# Restore WARN verdict for warn_commands instead of collapsing to BLOCK
def _web_ask(self, tool, detail, reason, rule=None):
    verdict = Verdict.WARN if reason.startswith('⚠') else Verdict.BLOCK
    clean   = reason.lstrip('⚠ ').strip()
    return Decision(verdict, clean, rule=rule, action=detail)

fw._ask = types.MethodType(_web_ask, fw)

# ── Helpers ───────────────────────────────────────────────────────────
def load_events(limit=25):
    events = []
    if AUDIT.exists():
        with open(AUDIT) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except Exception:
                        pass
    return list(reversed(events[-limit:]))

# ── Routes ────────────────────────────────────────────────────────────
@app.route('/')
def index():
    events  = load_events()
    total   = len(events)
    blocked = sum(1 for e in events if e.get('verdict') == 'block')
    allowed = sum(1 for e in events if e.get('verdict') == 'allow')
    rate    = round(blocked / total * 100) if total else 0
    return render_template('index.html',
        events=events, total=total,
        blocked=blocked, allowed=allowed, rate=rate)

@app.route('/api/check', methods=['POST'])
def check():
    data  = request.get_json(silent=True) or {}
    kind  = data.get('type', 'bash')
    value = (data.get('value') or '').strip()
    if not value:
        return jsonify({'error': 'empty value'}), 400
    try:
        dispatch = {
            'bash':        lambda: fw.check_bash(value),
            'file_read':   lambda: fw.check_file_read(value),
            'file_write':  lambda: fw.check_file_write(value),
            'file_delete': lambda: fw.check_file_delete(value),
            'env':         lambda: fw.check_env_access(value),
        }
        if kind not in dispatch:
            return jsonify({'error': 'unknown type'}), 400
        d = dispatch[kind]()
        return jsonify({
            'verdict':  d.verdict.value,
            'reason':   d.reason,
            'rule':     d.rule,
            'category': d.category,
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)), debug=False)

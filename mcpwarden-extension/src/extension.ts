import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';

let proxyProcess: cp.ChildProcess | null = null;
let statusBar: vscode.StatusBarItem;
let outputChannel: vscode.OutputChannel;
let blockedCount = 0;
let allowedCount = 0;
let isRunning    = false;

export function activate(context: vscode.ExtensionContext) {
  outputChannel = vscode.window.createOutputChannel('MCPWarden');
  statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBar.command = 'mcpwarden.showLog';
  statusBar.show();
  updateStatusBar('stopped');
  context.subscriptions.push(
    vscode.commands.registerCommand('mcpwarden.start',      () => startProxy(context)),
    vscode.commands.registerCommand('mcpwarden.stop',       () => stopProxy()),
    vscode.commands.registerCommand('mcpwarden.showLog',    () => showAuditLog(context)),
    vscode.commands.registerCommand('mcpwarden.openPolicy', () => openPolicy(context)),
    vscode.commands.registerCommand('mcpwarden.resetStats', () => resetStats()),
    statusBar, outputChannel,
  );
  const cfg = vscode.workspace.getConfiguration('mcpwarden');
  if (cfg.get<boolean>('autoStart', true)) { startProxy(context); }
}

export function deactivate() { stopProxy(); }

async function startProxy(context: vscode.ExtensionContext) {
  if (proxyProcess) {
    vscode.window.showInformationMessage('MCPWarden is already running.');
    return;
  }
  const python = await resolvePython();
  if (!python) {
    vscode.window.showErrorMessage('MCPWarden: Python not found. Set mcpwarden.pythonPath.');
    return;
  }
  await ensurePyYaml(python);

  const mcpScript     = path.join(context.extensionPath, 'python', 'mcp_server.py');
  const policyPath    = resolvePolicy(context);
  const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? os.homedir();

  outputChannel.appendLine('[MCPWarden] Starting...');
  outputChannel.appendLine('[MCPWarden] Policy : ' + policyPath);
  outputChannel.appendLine('[MCPWarden] Python : ' + python);

  proxyProcess = cp.spawn(python, [mcpScript, '--config', policyPath], {
    cwd: workspaceRoot,
    env: { ...process.env, PROJECT_ROOT: workspaceRoot },
  });

  proxyProcess.stdout?.on('data', (d: Buffer) => outputChannel.append(d.toString()));
  proxyProcess.stderr?.on('data', (d: Buffer) => {
    const t = d.toString();
    outputChannel.append(t);
    parseLine(t);
  });
  proxyProcess.on('exit', (code) => {
    outputChannel.appendLine('[MCPWarden] Exited (code ' + code + ')');
    isRunning = false; proxyProcess = null; updateStatusBar('stopped');
  });
  proxyProcess.on('error', (err) => {
    vscode.window.showErrorMessage('MCPWarden: ' + err.message);
    isRunning = false; proxyProcess = null; updateStatusBar('stopped');
  });

  await sleep(600);
  if (proxyProcess && !proxyProcess.killed) {
    isRunning = true;
    updateStatusBar('running');
    outputChannel.appendLine('[MCPWarden] Ready.');
  }
}

function stopProxy() {
  if (!proxyProcess) { return; }
  proxyProcess.kill('SIGTERM');
  proxyProcess = null; isRunning = false; updateStatusBar('stopped');
  outputChannel.appendLine('[MCPWarden] Stopped.');
}

function parseLine(text: string) {
  const cfg = vscode.workspace.getConfiguration('mcpwarden');
  for (const line of text.split('\n')) {
    if (line.includes('BLOCKED') || line.includes('\u{1F6AB}')) {
      blockedCount++; updateStatusBar('running');
      if (cfg.get<boolean>('showNotifications', true)) {
        const reason = line.replace(/.*BLOCKED[^:]*:\s*/, '').trim().slice(0, 80);
        vscode.window.showWarningMessage('MCPWarden blocked: ' + reason, 'View Log')
          .then(s => { if (s === 'View Log') { outputChannel.show(); } });
      }
    }
    if (line.includes('ALLOW')) { allowedCount++; updateStatusBar('running'); }
  }
}

function updateStatusBar(state: 'running' | 'stopped') {
  if (state === 'stopped') {
    statusBar.text = '$(shield) MCPWarden: OFF';
    statusBar.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
    statusBar.tooltip = 'MCPWarden stopped — click to view log';
  } else {
    const b = blockedCount > 0 ? ' | Blocked: ' + blockedCount : '';
    statusBar.text = '$(shield) MCPWarden' + b;
    statusBar.backgroundColor = new vscode.ThemeColor('statusBarItem.prominentBackground');
    statusBar.tooltip = 'Running — Allowed: ' + allowedCount + '  Blocked: ' + blockedCount;
  }
}

function resetStats() {
  blockedCount = 0; allowedCount = 0;
  updateStatusBar(isRunning ? 'running' : 'stopped');
}

async function showAuditLog(context: vscode.ExtensionContext) {
  const ws = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  const candidates = [
    ws ? path.join(ws, 'logs', 'audit.jsonl') : null,
    path.join(context.extensionPath, 'python', 'logs', 'audit.jsonl'),
  ].filter(Boolean) as string[];
  for (const p of candidates) {
    if (fs.existsSync(p)) {
      const doc = await vscode.workspace.openTextDocument(p);
      await vscode.window.showTextDocument(doc, { preview: false });
      return;
    }
  }
  outputChannel.show();
}

function openPolicy(context: vscode.ExtensionContext) {
  vscode.workspace.openTextDocument(resolvePolicy(context))
    .then(d => vscode.window.showTextDocument(d));
}

function resolvePolicy(context: vscode.ExtensionContext): string {
  const ws = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (ws) {
    const p = path.join(ws, 'config', 'policy.yaml');
    if (fs.existsSync(p)) { return p; }
  }
  return path.join(context.extensionPath, 'python', 'config', 'policy.yaml');
}

async function resolvePython(): Promise<string | null> {
  const cfg = vscode.workspace.getConfiguration('mcpwarden').get<string>('pythonPath', '');
  if (cfg) { return cfg; }
  for (const name of ['python3', 'python']) {
    try { cp.execSync(name + ' --version', { stdio: 'ignore' }); return name; }
    catch { continue; }
  }
  return null;
}

async function ensurePyYaml(python: string) {
  try { cp.execSync(python + ' -c "import yaml"', { stdio: 'ignore' }); }
  catch {
    try { cp.execSync(python + ' -m pip install pyyaml --quiet --break-system-packages', { stdio: 'pipe' }); }
    catch { vscode.window.showWarningMessage('MCPWarden: run pip install pyyaml manually'); }
  }
}

function sleep(ms: number) { return new Promise(r => setTimeout(r, ms)); }

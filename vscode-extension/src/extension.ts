/**
 * squash-ai VS Code Extension — Main entry point.
 *
 * Provides:
 *   - Status bar item showing overall compliance score
 *   - Sidebar tree: Model Portfolio, Active Violations, Regulatory Deadlines
 *   - Commands: Run Attestation, Show Dashboard, Bias Audit, Annex IV, ISO 42001,
 *               Publish Attestation, Export Trust Package
 *   - Auto-watch: re-attests when model files change (configurable)
 */

import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as path from 'path';
import * as fs from 'fs';

// ── Types ─────────────────────────────────────────────────────────────────────

interface AttestationResult {
  model_id?: string;
  compliance_score?: number;
  policies_checked?: string[];
  violations?: unknown[];
  attested_at?: string;
  passed?: boolean;
}

interface ModelPortfolioItem {
  modelId: string;
  modelPath: string;
  score: number | null;
  violations: number;
  lastAttested: string | null;
  riskTier: string;
}

// ── Status Bar ────────────────────────────────────────────────────────────────

let statusBarItem: vscode.StatusBarItem;

function updateStatusBar(score: number | null, violations: number): void {
  if (!statusBarItem) return;
  if (score === null) {
    statusBarItem.text = '$(shield) Squash: ?';
    statusBarItem.tooltip = 'Squash AI Compliance — no attestation found. Run "Squash: Run Attestation".';
    statusBarItem.backgroundColor = undefined;
  } else if (score >= 80 && violations === 0) {
    statusBarItem.text = `$(shield) Squash: ${score.toFixed(0)}% ✓`;
    statusBarItem.tooltip = `Squash AI Compliance — Score: ${score.toFixed(1)}% — ${violations} violations`;
    statusBarItem.backgroundColor = undefined;
  } else if (score >= 60) {
    statusBarItem.text = `$(warning) Squash: ${score.toFixed(0)}%`;
    statusBarItem.tooltip = `Squash AI Compliance — Score: ${score.toFixed(1)}% — ${violations} violations`;
    statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
  } else {
    statusBarItem.text = `$(error) Squash: ${score.toFixed(0)}%`;
    statusBarItem.tooltip = `Squash AI Compliance — Score: ${score.toFixed(1)}% — ${violations} violations`;
    statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
  }
  statusBarItem.show();
}

// ── CLI runner ────────────────────────────────────────────────────────────────

async function runSquash(args: string[]): Promise<{ stdout: string; stderr: string; code: number }> {
  const config = vscode.workspace.getConfiguration('squash');
  const cli = config.get<string>('cliPath', 'squash');
  const cwd = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? process.cwd();

  return new Promise((resolve) => {
    cp.execFile(cli, args, { cwd, timeout: 120_000 }, (err, stdout, stderr) => {
      resolve({
        stdout: stdout ?? '',
        stderr: stderr ?? '',
        code: (err as NodeJS.ErrnoException & { code?: number })?.code ?? (err ? 1 : 0),
      });
    });
  });
}

// ── Tree data providers ───────────────────────────────────────────────────────

class ModelPortfolioProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<vscode.TreeItem | undefined | null>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private items: ModelPortfolioItem[] = [];

  refresh(items?: ModelPortfolioItem[]): void {
    if (items) this.items = items;
    this._onDidChangeTreeData.fire(null);
  }

  getTreeItem(element: vscode.TreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(): vscode.TreeItem[] {
    if (this.items.length === 0) {
      const item = new vscode.TreeItem('No models found. Run "Squash: Run Attestation".');
      item.iconPath = new vscode.ThemeIcon('info');
      return [item];
    }
    return this.items.map((m) => {
      const score = m.score !== null ? `${m.score.toFixed(0)}%` : 'N/A';
      const label = `${m.modelId} — ${score}`;
      const item = new vscode.TreeItem(label);
      item.description = m.riskTier;
      item.tooltip = `${m.modelId}\nScore: ${score}\nViolations: ${m.violations}\nLast attested: ${m.lastAttested ?? 'never'}`;
      item.iconPath = new vscode.ThemeIcon(
        m.score !== null && m.score >= 80 && m.violations === 0
          ? 'pass'
          : m.score !== null && m.score >= 60
          ? 'warning'
          : 'error'
      );
      return item;
    });
  }
}

class ViolationsProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<vscode.TreeItem | undefined | null>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private violations: string[] = [];

  refresh(violations: string[]): void {
    this.violations = violations;
    this._onDidChangeTreeData.fire(null);
  }

  getTreeItem(element: vscode.TreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(): vscode.TreeItem[] {
    if (this.violations.length === 0) {
      const item = new vscode.TreeItem('No active violations ✓');
      item.iconPath = new vscode.ThemeIcon('pass');
      return [item];
    }
    return this.violations.map((v) => {
      const item = new vscode.TreeItem(v);
      item.iconPath = new vscode.ThemeIcon('warning');
      return item;
    });
  }
}

class DeadlinesProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<vscode.TreeItem | undefined | null>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  refresh(): void {
    this._onDidChangeTreeData.fire(null);
  }

  getTreeItem(element: vscode.TreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(): vscode.TreeItem[] {
    const today = new Date();
    const euDate = new Date('2026-08-02');
    const colDate = new Date('2026-06-01');
    const euDays = Math.max(0, Math.ceil((euDate.getTime() - today.getTime()) / 86400000));
    const colDays = Math.max(0, Math.ceil((colDate.getTime() - today.getTime()) / 86400000));

    const makeItem = (label: string, days: number): vscode.TreeItem => {
      const item = new vscode.TreeItem(`${label} — ${days} days`);
      item.iconPath = new vscode.ThemeIcon(days < 30 ? 'error' : days < 90 ? 'warning' : 'calendar');
      return item;
    };

    return [
      makeItem('EU AI Act enforcement', euDays),
      makeItem('Colorado AI Act', colDays),
      makeItem('ISO 42001 (recommended)', 245),
    ];
  }
}

// ── Extension activation ──────────────────────────────────────────────────────

export function activate(context: vscode.ExtensionContext): void {
  const config = vscode.workspace.getConfiguration('squash');

  // Status bar
  if (config.get<boolean>('showStatusBar', true)) {
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    statusBarItem.command = 'squash.showDashboard';
    context.subscriptions.push(statusBarItem);
    updateStatusBar(null, 0);
  }

  // Tree providers
  const portfolioProvider = new ModelPortfolioProvider();
  const violationsProvider = new ViolationsProvider();
  const deadlinesProvider = new DeadlinesProvider();

  context.subscriptions.push(
    vscode.window.registerTreeDataProvider('squash.modelPortfolio', portfolioProvider),
    vscode.window.registerTreeDataProvider('squash.violations', violationsProvider),
    vscode.window.registerTreeDataProvider('squash.deadlines', deadlinesProvider),
  );

  // Helper: run attestation and refresh all views
  async function runAndRefresh(modelPath: string): Promise<void> {
    const policy = config.get<string>('defaultPolicy', 'eu-ai-act');
    await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Notification, title: 'Squash: Running attestation…', cancellable: false },
      async () => {
        const result = await runSquash(['attest', modelPath, '--policy', policy, '--json-result', '/tmp/squash-result.json']);
        if (result.code === 0) {
          vscode.window.showInformationMessage(`Squash: attestation passed for ${path.basename(modelPath)}`);
        } else {
          vscode.window.showWarningMessage(`Squash: attestation completed with findings. Check output.`);
        }
        // Try to parse result
        try {
          const data: AttestationResult = JSON.parse(fs.readFileSync('/tmp/squash-result.json', 'utf8'));
          const score = typeof data.compliance_score === 'number' ? data.compliance_score : null;
          const violations = Array.isArray(data.violations) ? data.violations.length : 0;
          updateStatusBar(score, violations);
          portfolioProvider.refresh([{
            modelId: data.model_id ?? path.basename(modelPath),
            modelPath,
            score,
            violations,
            lastAttested: data.attested_at ?? new Date().toISOString(),
            riskTier: 'unknown',
          }]);
        } catch {
          // result file not written — non-fatal
        }
      }
    );
  }

  // ── Commands ────────────────────────────────────────────────────────────────

  context.subscriptions.push(
    vscode.commands.registerCommand('squash.runAttestation', async (uri?: vscode.Uri) => {
      const modelPath = uri?.fsPath
        ?? vscode.workspace.workspaceFolders?.[0]?.uri.fsPath
        ?? '.';
      await runAndRefresh(modelPath);
    }),

    vscode.commands.registerCommand('squash.showDashboard', async () => {
      const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? '.';
      const result = await runSquash(['dashboard', '--models-dir', workspaceRoot, '--json']);
      if (result.stdout) {
        const panel = vscode.window.createWebviewPanel(
          'squashDashboard', 'Squash Dashboard',
          vscode.ViewColumn.One, {}
        );
        panel.webview.html = _dashboardHtml(result.stdout);
      } else {
        vscode.window.showErrorMessage('Squash: Could not load dashboard. Is squash installed?');
      }
    }),

    vscode.commands.registerCommand('squash.runBiasAudit', async () => {
      const pred = await vscode.window.showOpenDialog({
        canSelectFiles: true, filters: { CSV: ['csv'] },
        openLabel: 'Select predictions CSV',
      });
      if (!pred || !pred[0]) return;
      const protected_attrs = await vscode.window.showInputBox({
        prompt: 'Protected attribute column names (comma-separated)',
        placeHolder: 'age_group,gender',
      });
      if (!protected_attrs) return;
      const result = await runSquash(['bias-audit', '--predictions', pred[0].fsPath, '--protected', protected_attrs]);
      const channel = vscode.window.createOutputChannel('Squash Bias Audit');
      channel.appendLine(result.stdout || result.stderr);
      channel.show();
    }),

    vscode.commands.registerCommand('squash.generateAnnexIV', async (uri?: vscode.Uri) => {
      const modelPath = uri?.fsPath ?? vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? '.';
      const result = await runSquash(['annex-iv', 'generate', '--root', modelPath]);
      const channel = vscode.window.createOutputChannel('Squash Annex IV');
      channel.appendLine(result.stdout || result.stderr);
      channel.show();
    }),

    vscode.commands.registerCommand('squash.runIso42001', async (uri?: vscode.Uri) => {
      const modelPath = uri?.fsPath ?? vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? '.';
      const result = await runSquash(['iso42001', modelPath]);
      const channel = vscode.window.createOutputChannel('Squash ISO 42001');
      channel.appendLine(result.stdout || result.stderr);
      channel.show();
    }),

    vscode.commands.registerCommand('squash.publishAttestation', async (uri?: vscode.Uri) => {
      const modelPath = uri?.fsPath ?? vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? '.';
      const org = await vscode.window.showInputBox({ prompt: 'Organization name', placeHolder: 'my-company' });
      if (!org) return;
      const result = await runSquash(['publish', modelPath, '--org', org]);
      vscode.window.showInformationMessage(`Squash: ${result.stdout || result.stderr}`);
    }),

    vscode.commands.registerCommand('squash.exportTrustPackage', async (uri?: vscode.Uri) => {
      const modelPath = uri?.fsPath ?? vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? '.';
      const result = await runSquash(['trust-package', modelPath]);
      const channel = vscode.window.createOutputChannel('Squash Trust Package');
      channel.appendLine(result.stdout || result.stderr);
      channel.show();
    }),

    vscode.commands.registerCommand('squash.openReport', async () => {
      const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? '.';
      const candidates = [
        path.join(workspaceRoot, 'squash_attestation.json'),
        path.join(workspaceRoot, 'squash-attest.json'),
      ];
      for (const c of candidates) {
        if (fs.existsSync(c)) {
          const doc = await vscode.workspace.openTextDocument(c);
          vscode.window.showTextDocument(doc);
          return;
        }
      }
      vscode.window.showWarningMessage('No squash attestation report found. Run attestation first.');
    }),

    vscode.commands.registerCommand('squash.refreshTree', () => {
      portfolioProvider.refresh();
      violationsProvider.refresh([]);
      deadlinesProvider.refresh();
    }),
  );

  // Auto-watch if enabled
  if (config.get<boolean>('autoAttest', false)) {
    const watcher = vscode.workspace.createFileSystemWatcher('**/*.{gguf,bin,safetensors,pt,pth}');
    watcher.onDidChange(async (uri) => {
      const dir = path.dirname(uri.fsPath);
      await runAndRefresh(dir);
    });
    context.subscriptions.push(watcher);
  }
}

export function deactivate(): void {
  statusBarItem?.dispose();
}

// ── Webview helpers ───────────────────────────────────────────────────────────

function _dashboardHtml(jsonData: string): string {
  let data: Record<string, unknown>;
  try {
    data = JSON.parse(jsonData);
  } catch {
    return `<html><body><pre>${jsonData}</pre></body></html>`;
  }
  const score = (data.overall_score as number | null) ?? null;
  const models = (data.models as { total: number; passing: number; failing: number; unattested: number }) ?? { total: 0, passing: 0, failing: 0, unattested: 0 };
  const violations = (data.violations as { total: number; critical: number }) ?? { total: 0, critical: 0 };
  const deadline = (data.next_deadline as { label: string; days_remaining: number }) ?? { label: '?', days_remaining: 0 };

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: var(--vscode-editor-background); color: var(--vscode-editor-foreground);
         padding: 24px; }
  h1 { color: var(--vscode-textLink-foreground); font-size: 1.4em; }
  .metric-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 16px; margin: 24px 0; }
  .metric-card { background: var(--vscode-sideBar-background); border-radius: 8px; padding: 16px;
                 border: 1px solid var(--vscode-panel-border); }
  .metric-value { font-size: 2em; font-weight: bold; }
  .metric-label { font-size: 0.85em; opacity: 0.7; margin-top: 4px; }
  .green { color: #4ec9b0; } .yellow { color: #dcdcaa; } .red { color: #f44747; }
</style>
</head>
<body>
<h1>⚡ Squash AI Compliance Dashboard</h1>
<div class="metric-grid">
  <div class="metric-card">
    <div class="metric-value ${score !== null && score >= 80 ? 'green' : score !== null && score >= 60 ? 'yellow' : 'red'}">${score !== null ? score.toFixed(1) + '%' : 'N/A'}</div>
    <div class="metric-label">Overall Compliance Score</div>
  </div>
  <div class="metric-card">
    <div class="metric-value">${models.total}</div>
    <div class="metric-label">Models · ${models.passing} pass · ${models.failing} fail · ${models.unattested} unattested</div>
  </div>
  <div class="metric-card">
    <div class="metric-value ${violations.total > 0 ? 'red' : 'green'}">${violations.total}</div>
    <div class="metric-label">Policy Violations (${violations.critical} critical)</div>
  </div>
  <div class="metric-card">
    <div class="metric-value ${deadline.days_remaining < 30 ? 'red' : deadline.days_remaining < 90 ? 'yellow' : 'green'}">${deadline.days_remaining}</div>
    <div class="metric-label">Days · ${deadline.label}</div>
  </div>
</div>
<p style="opacity: 0.6; font-size: 0.85em;">Generated by <strong>squash-ai</strong> · <a href="https://getsquash.dev" style="color: var(--vscode-textLink-foreground)">getsquash.dev</a></p>
</body></html>`;
}

import * as vscode from "vscode";
import fs from "fs";
import path from "path";

import {
  analyze,
  loadConfig,
  isIgnored,
  getPreviousContent,
  computeChangedLines,
  isGitRepo,
  blameLine,
  explainFinding,
  isAiAvailable,
  aiKeyEnv,
  describeProvider,
  runGate,
  reviewChanges,
  deepReview,
  resolveProvider,
  DEFAULT_CONFIG,
  TIER_META,
  TIER_ORDER,
} from "../../src/core/index.js";
import type { Finding, AnalyzeResult, Config } from "../../src/core/types.js";

// --- module state ------------------------------------------------------------
let diagnostics: vscode.DiagnosticCollection;
let statusBar: vscode.StatusBarItem;
let aiChannel: vscode.OutputChannel;
let gateChannel: vscode.OutputChannel;
let deepChannel: vscode.OutputChannel;
let riskTree: RiskTreeProvider;
const findingsByUri = new Map<string, { res: AnalyzeResult; folder: string; config: Config }>();
const configCache = new Map<string, Config>();
const debounceTimers = new Map<string, ReturnType<typeof setTimeout>>();
export const verdictCache = new Map<string, { verdict: string; steps: number; model: string; hitMax: boolean }>();

const MAX_BYTES = 2 * 1024 * 1024;

// --- helpers -----------------------------------------------------------------
function settings(): vscode.WorkspaceConfiguration {
  return vscode.workspace.getConfiguration("diffgate");
}

function folderForUri(uri: vscode.Uri): string {
  const wf = vscode.workspace.getWorkspaceFolder(uri);
  return wf ? wf.uri.fsPath : path.dirname(uri.fsPath);
}

function getConfigFor(folder: string): Config {
  if (!configCache.has(folder)) {
    let cfg: Config;
    try {
      cfg = loadConfig(folder).config;
    } catch (e) {
      vscode.window.showWarningMessage(`DiffGate: ${(e as Error).message}`);
      cfg = JSON.parse(JSON.stringify(DEFAULT_CONFIG)) as Config;
    }
    configCache.set(folder, cfg);
  }
  const cfg = configCache.get(folder)!;
  const merged: Config = { ...cfg, ai: { ...cfg.ai, enabled: cfg.ai.enabled || settings().get("ai.enabled", false) } };
  const provider = settings().get<string>("ai.provider", "");
  const model = settings().get<string>("ai.model", "");
  const deepModel_ = settings().get<string>("ai.deepReview.model", "");
  if (provider) merged.ai.provider = provider;
  if (model) merged.ai.model = model;
  if (deepModel_) {
    merged.ai.deepReview = { ...(merged.ai.deepReview || {}), model: deepModel_ };
  }
  return merged;
}

function severityFor(f: Finding): vscode.DiagnosticSeverity {
  if (f.blocking) return vscode.DiagnosticSeverity.Error;
  switch (f.tier) {
    case "orange": return vscode.DiagnosticSeverity.Warning;
    case "yellow": return vscode.DiagnosticSeverity.Information;
    default: return vscode.DiagnosticSeverity.Hint;
  }
}

function buildRange(finding: Finding, document: vscode.TextDocument | null): vscode.Range {
  const startLine = Math.max(0, finding.line - 1);
  const startCol = Math.max(0, finding.column ?? 0);
  let endLine = Math.max(0, (finding.endLine || finding.line) - 1);
  let endCol = finding.endColumn ?? startCol;
  if (endLine === startLine && endCol <= startCol) {
    if (document && startLine < document.lineCount) {
      return document.lineAt(startLine).range;
    }
    endCol = startCol + Math.max(1, (finding.code || "").length || 40);
  }
  return new vscode.Range(startLine, startCol, endLine, endCol);
}

function toDiagnostic(finding: Finding, document: vscode.TextDocument | null): vscode.Diagnostic {
  const d = new vscode.Diagnostic(buildRange(finding, document), `${finding.title}: ${finding.message}`, severityFor(finding));
  d.source = "diffgate";
  d.code = finding.ruleId;
  return d;
}

function analyzeText(filePath: string, content: string, folder: string, config: Config): AnalyzeResult {
  const scanMode = settings().get("scanMode", "diff");
  const diffMode = settings().get("diffMode", "working") as string;
  let changedLines = null;
  let previousContent = null;
  if (scanMode === "diff" && isGitRepo(folder)) {
    previousContent = getPreviousContent(folder, filePath, { mode: diffMode });
    if (previousContent != null) changedLines = computeChangedLines(previousContent, content);
  }
  return analyze({ filePath, content, previousContent, changedLines, config });
}

// --- per-document analysis ---------------------------------------------------
function analyzeDocument(document: vscode.TextDocument): void {
  if (!settings().get("enable", true)) return;
  if (document.uri.scheme !== "file") return;
  if (document.getText().length > MAX_BYTES) return;

  const folder = folderForUri(document.uri);
  const config = getConfigFor(folder);
  if (isIgnored(document.uri.fsPath, config, folder)) {
    diagnostics.delete(document.uri);
    findingsByUri.delete(document.uri.toString());
    return;
  }

  let res: AnalyzeResult;
  try {
    res = analyzeText(document.uri.fsPath, document.getText(), folder, config);
  } catch {
    return;
  }
  diagnostics.set(document.uri, res.findings.map((f) => toDiagnostic(f, document)));
  findingsByUri.set(document.uri.toString(), { res, folder, config });
  for (const key of verdictCache.keys()) {
    if (key.startsWith(document.uri.toString() + "::")) verdictCache.delete(key);
  }

  if (vscode.window.activeTextEditor?.document === document) updateStatusBar(res);

  if (settings().get("runGateOnSave", false) && res.findings.some((f) => f.tier === "orange")) {
    runGateForFolder(folder, config, res.findings);
  }
}

function debouncedAnalyze(document: vscode.TextDocument, delay = 350): void {
  const key = document.uri.toString();
  clearTimeout(debounceTimers.get(key));
  debounceTimers.set(key, setTimeout(() => {
    debounceTimers.delete(key);
    analyzeDocument(document);
  }, delay));
}

// --- status bar --------------------------------------------------------------
function updateStatusBar(res: AnalyzeResult): void {
  if (!res || res.findings.length === 0) {
    statusBar.text = "$(shield) DiffGate: clear";
    statusBar.tooltip = "No guardrail findings on changed lines";
    statusBar.backgroundColor = undefined;
    statusBar.show();
    return;
  }
  const { green, yellow, orange } = res.counts;
  statusBar.text = `$(shield) ${TIER_META[res.tier].icon} ${green}/${yellow}/${orange}`;
  statusBar.tooltip = `DiffGate: ${orange} orange · ${yellow} yellow · ${green} green — click to review all changes`;
  statusBar.backgroundColor =
    res.tier === "orange" ? new vscode.ThemeColor("statusBarItem.warningBackground") : undefined;
  statusBar.show();
}

// --- hover -------------------------------------------------------------------
const hoverProvider: vscode.HoverProvider = {
  provideHover(document: vscode.TextDocument, position: vscode.Position): vscode.Hover | undefined {
    const entry = findingsByUri.get(document.uri.toString());
    if (!entry) return;
    const here = entry.res.findings.filter((f) => f.line === position.line + 1);
    if (here.length === 0) return;

    const md = new vscode.MarkdownString(undefined, true);
    md.isTrusted = true;
    for (const f of here) {
      const meta = TIER_META[f.tier];
      md.appendMarkdown(`**${meta.icon} ${f.title}**  \`${f.ruleId}\`\n\n`);
      md.appendMarkdown(`${f.message}\n\n`);
      const vKey = `${document.uri.toString()}::${f.ruleId}::${f.line}`;
      const cached = verdictCache.get(vKey);
      if (cached) {
        const vLower = cached.verdict.toLowerCase();
        let badge: string;
        if (/confirmed.risk|exploitable|high.risk|critical/.test(vLower)) {
          badge = "$(error) **Confirmed risk**";
        } else if (/likely.safe|low.risk|no.exploit|benign/.test(vLower)) {
          badge = "$(pass) **Likely safe**";
        } else {
          badge = "$(question) **Needs human review**";
        }
        const firstLine = cached.verdict.split("\n").find((l) => l.trim()) || cached.verdict;
        md.appendMarkdown(`> ${badge}: _${firstLine.slice(0, 120).trim()}${firstLine.length > 120 ? "…" : ""}_\n\n`);
        if (cached.hitMax) md.appendMarkdown(`> _(step limit hit — result may be incomplete)_\n\n`);
      }
      const b = blameLine(entry.folder, document.uri.fsPath, f.line);
      if (b && b.author) {
        md.appendMarkdown(`_Baseline owner: ${b.author}${b.hash ? " · " + b.hash : ""}_\n\n`);
      }
      const args = encodeURIComponent(JSON.stringify([document.uri.toString(), f.ruleId, f.line]));
      const links = [`[$(sparkle) Explain with AI](command:diffgate.explainWithAI?${args})`];
      if (f.tier === "orange") links.push(`[$(beaker) Deep Review](command:diffgate.deepReview?${args})`);
      if (f.fix) links.push("Quick fix available (`⌘.` / `Ctrl+.`)");
      md.appendMarkdown(links.join("  ·  ") + "\n\n---\n");
    }
    return new vscode.Hover(md);
  },
};

// --- code actions (quick fixes) ---------------------------------------------
const codeActionProvider: vscode.CodeActionProvider = {
  provideCodeActions(document: vscode.TextDocument, _range: vscode.Range, context: vscode.CodeActionContext): vscode.CodeAction[] {
    const entry = findingsByUri.get(document.uri.toString());
    if (!entry) return [];
    const actions: vscode.CodeAction[] = [];
    const diags = context.diagnostics.filter((d) => d.source === "diffgate");
    for (const diag of diags) {
      const f = entry.res.findings.find((x) => x.ruleId === diag.code && x.line === diag.range.start.line + 1);
      if (!f) continue;

      if (f.fix) {
        const a = new vscode.CodeAction(`DiffGate: ${f.fix.title}`, vscode.CodeActionKind.QuickFix);
        a.edit = new vscode.WorkspaceEdit();
        a.edit.replace(document.uri, new vscode.Range(f.fix.startLine - 1, f.fix.startColumn, f.fix.endLine - 1, f.fix.endColumn), f.fix.newText);
        a.diagnostics = [diag];
        a.isPreferred = true;
        actions.push(a);
      }

      const explain = new vscode.CodeAction(`DiffGate: Explain "${f.title}" with AI`, vscode.CodeActionKind.QuickFix);
      explain.command = { command: "diffgate.explainWithAI", title: "Explain", arguments: [document.uri.toString(), f.ruleId, f.line] };
      actions.push(explain);

      if (f.tier === "orange") {
        const deep = new vscode.CodeAction(`DiffGate: Deep Review "${f.title}" (agentic)`, vscode.CodeActionKind.QuickFix);
        deep.command = { command: "diffgate.deepReview", title: "Deep Review", arguments: [document.uri.toString(), f.ruleId, f.line] };
        actions.push(deep);
      }

      const ignore = new vscode.CodeAction(`DiffGate: Disable rule "${f.ruleId}" for this project`, vscode.CodeActionKind.QuickFix);
      ignore.command = { command: "diffgate.ignoreRule", title: "Disable rule", arguments: [entry.folder, f.ruleId] };
      actions.push(ignore);
    }
    return actions;
  },
};

// --- risk tree view ----------------------------------------------------------
interface TreeNode { kind: string; item: vscode.TreeItem; file?: AnalyzeResult; }

class RiskTreeProvider implements vscode.TreeDataProvider<TreeNode> {
  private files: AnalyzeResult[] = [];
  private _emitter = new vscode.EventEmitter<TreeNode | undefined>();
  readonly onDidChangeTreeData = this._emitter.event;

  setData(files: AnalyzeResult[]): void {
    this.files = files;
    this._emitter.fire(undefined);
  }
  getTreeItem(el: TreeNode): vscode.TreeItem { return el.item; }
  getChildren(el?: TreeNode): TreeNode[] {
    if (!el) {
      if (this.files.length === 0) {
        const item = new vscode.TreeItem("No pending findings — clear ✔");
        item.iconPath = new vscode.ThemeIcon("pass");
        return [{ kind: "empty", item }];
      }
      return this.files.map((f) => this.fileNode(f));
    }
    if (el.kind === "file" && el.file) return el.file.findings.map((fd) => this.findingNode(el.file!, fd));
    return [];
  }
  private fileNode(file: AnalyzeResult): TreeNode {
    const rel = vscode.workspace.asRelativePath(file.filePath);
    const item = new vscode.TreeItem(rel, vscode.TreeItemCollapsibleState.Expanded);
    const { green, yellow, orange } = file.counts;
    item.description = `${TIER_META[file.tier].icon} ${orange}/${yellow}/${green}`;
    item.resourceUri = vscode.Uri.file(file.filePath);
    item.iconPath = vscode.ThemeIcon.File;
    return { kind: "file", file, item };
  }
  private findingNode(file: AnalyzeResult, f: Finding): TreeNode {
    const item = new vscode.TreeItem(`L${f.line}  ${f.title}`, vscode.TreeItemCollapsibleState.None);
    item.description = f.ruleId;
    item.tooltip = f.message;
    const colorMap: Record<string, string> = { green: "charts.green", yellow: "charts.yellow", orange: "charts.orange" };
    const color = colorMap[f.tier];
    item.iconPath = new vscode.ThemeIcon("circle-filled", new vscode.ThemeColor(color));
    item.command = {
      command: "vscode.open", title: "Open",
      arguments: [vscode.Uri.file(file.filePath), { selection: new vscode.Range(f.line - 1, 0, f.line - 1, 0) }],
    };
    return { kind: "finding", item };
  }
}

// --- workspace review --------------------------------------------------------
function refreshWorkspace(): void {
  const folders = vscode.workspace.workspaceFolders || [];
  const diffMode = settings().get<string>("diffMode", "working");
  const all: AnalyzeResult[] = [];
  for (const wf of folders) {
    const cwd = wf.uri.fsPath;
    if (!isGitRepo(cwd)) continue;
    let review: ReturnType<typeof reviewChanges>;
    try {
      review = reviewChanges(cwd, { mode: diffMode });
    } catch {
      continue;
    }
    for (const fr of review.files) {
      all.push(fr);
      const uri = vscode.Uri.file(fr.filePath);
      if (!findingsByUri.has(uri.toString())) {
        diagnostics.set(uri, fr.findings.map((f) => toDiagnostic(f, null)));
      }
      const config = getConfigFor(cwd);
      findingsByUri.set(uri.toString(), { res: fr, folder: cwd, config });
    }
  }
  riskTree.setData(all);
}

// --- gate --------------------------------------------------------------------
async function runGateForFolder(folder: string, config: Config, findings: Finding[]): Promise<void> {
  if (!config.testCommand) return;
  gateChannel.show(true);
  gateChannel.appendLine(`\n$ ${config.testCommand}   (cwd: ${folder})`);
  const result = await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Window, title: "DiffGate: running verification gate…" },
    () => runGate({ cwd: folder, config, findings })
  );
  if (!result.ran) {
    gateChannel.appendLine(`(skipped: ${result.reason})`);
    return;
  }
  const r = result as { stdout?: string; stderr?: string; success?: boolean; durationMs?: number; code?: number };
  gateChannel.appendLine(((r.stdout || "") + (r.stderr || "")).trim());
  if (r.success) {
    vscode.window.showInformationMessage(`Guardrail gate passed (${((r.durationMs ?? 0) / 1000).toFixed(1)}s).`);
  } else {
    vscode.window.showErrorMessage(`Guardrail gate FAILED (exit ${r.code}). See "Guardrail Gate" output.`);
  }
}

// --- commands ----------------------------------------------------------------
async function cmdExplainWithAI(uriStr: string, ruleId: string, line: number): Promise<void> {
  const entry = findingsByUri.get(uriStr);
  if (!entry) return;
  const f = entry.res.findings.find((x) => x.ruleId === ruleId && x.line === line);
  if (!f) return;
  if (!isAiAvailable(entry.config)) {
    vscode.window.showWarningMessage(`Guardrail AI is off. Enable diffgate.ai.enabled and set $${aiKeyEnv(entry.config)} (provider: ${describeProvider(entry.config)}).`);
    return;
  }
  let snippet = f.code;
  try {
    const doc = await vscode.workspace.openTextDocument(vscode.Uri.parse(uriStr));
    const lines = doc.getText().split("\n");
    snippet = lines.slice(Math.max(0, line - 5), line + 4).join("\n");
  } catch { /* fall back to f.code */ }
  aiChannel.show(true);
  aiChannel.appendLine(`\n=== ${f.title} [${ruleId}] @ ${path.basename(uriStr)}:${line} ===`);
  await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: "DiffGate: asking Claude…" },
    async () => {
      try {
        const { text, model } = await explainFinding({ finding: f, snippet, language: entry.res.language, config: entry.config });
        aiChannel.appendLine(`[${model}]`);
        aiChannel.appendLine(text);
      } catch (e) {
        aiChannel.appendLine(`Error: ${(e as Error).message}`);
        vscode.window.showErrorMessage(`Guardrail AI: ${(e as Error).message}`);
      }
    }
  );
}

async function cmdDeepReview(uriStr: string, ruleId: string, line: number): Promise<void> {
  const entry = findingsByUri.get(uriStr);
  if (!entry) return;
  const f = entry.res.findings.find((x) => x.ruleId === ruleId && x.line === line);
  if (!f) return;
  if (!isAiAvailable(entry.config)) {
    resolveProvider(entry.config); // validate config
    vscode.window.showWarningMessage(`Guardrail AI is off. Enable diffgate.ai.enabled and set $${aiKeyEnv(entry.config)} (provider: ${describeProvider(entry.config)}).`);
    return;
  }
  let snippet = f.code;
  try {
    const doc = await vscode.workspace.openTextDocument(vscode.Uri.parse(uriStr));
    const lines = doc.getText().split("\n");
    snippet = lines.slice(Math.max(0, line - 5), line + 4).join("\n");
  } catch { /* fall back to f.code */ }

  deepChannel.show(true);
  const label = `${f.title} [${ruleId}] @ ${path.basename(uriStr)}:${line}`;
  deepChannel.appendLine(`\n${"=".repeat(label.length + 8)}`);
  deepChannel.appendLine(`=== ${label} ===`);
  deepChannel.appendLine(`${"=".repeat(label.length + 8)}`);

  await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: "DiffGate: Deep Review in progress…", cancellable: true },
    async (progress, token) => {
      const ctl = new AbortController();
      token.onCancellationRequested(() => ctl.abort());
      try {
        const res = await deepReview({
          finding: f,
          filePath: path.relative(entry.folder, vscode.Uri.parse(uriStr).fsPath),
          snippet,
          language: entry.res.language,
          cwd: entry.folder,
          config: entry.config,
          signal: ctl.signal,
          onStep({ name, input }) {
            const summary = typeof input === "object" ? JSON.stringify(input).slice(0, 120) : String(input);
            deepChannel.appendLine(`  [tool] ${name}(${summary})`);
            progress.report({ message: `tool: ${name}` });
          },
        });
        const cacheKey = `${uriStr}::${ruleId}::${line}`;
        verdictCache.set(cacheKey, { verdict: res.verdict, steps: res.steps, model: res.model, hitMax: res.hitMax });
        deepChannel.appendLine(`\n[model: ${res.model}  steps: ${res.steps}${res.hitMax ? " (step limit hit)" : ""}]`);
        deepChannel.appendLine(res.verdict);
        if (res.hitMax) {
          vscode.window.showWarningMessage(`Guardrail Deep Review: reached step limit. See "Guardrail Deep Review" output.`);
        } else {
          vscode.window.showInformationMessage(`Deep Review complete — see "Guardrail Deep Review" output.`);
        }
      } catch (e) {
        if ((e as Error).name === "AbortError") {
          deepChannel.appendLine("(cancelled)");
        } else {
          deepChannel.appendLine(`Error: ${(e as Error).message}`);
          vscode.window.showErrorMessage(`Guardrail Deep Review: ${(e as Error).message}`);
        }
      }
    }
  );
}

function cmdIgnoreRule(folder: string, ruleId: string): void {
  const cfgPath = path.join(folder, ".diffgate.json");
  let raw: Record<string, unknown> = {};
  try {
    if (fs.existsSync(cfgPath)) raw = JSON.parse(fs.readFileSync(cfgPath, "utf-8")) as Record<string, unknown>;
  } catch {
    vscode.window.showErrorMessage(`DiffGate: ${cfgPath} is not valid JSON; not modifying.`);
    return;
  }
  raw["rules"] = (raw["rules"] as Record<string, unknown>) || {};
  (raw["rules"] as Record<string, unknown>)[ruleId] = false;
  fs.writeFileSync(cfgPath, JSON.stringify(raw, null, 2) + "\n");
  configCache.delete(folder);
  vscode.window.showInformationMessage(`DiffGate: rule "${ruleId}" disabled in .diffgate.json.`);
  reanalyzeOpen();
  refreshWorkspace();
}

async function cmdOpenConfig(): Promise<void> {
  const wf = vscode.workspace.workspaceFolders?.[0];
  if (!wf) return;
  const cfgPath = path.join(wf.uri.fsPath, ".diffgate.json");
  if (!fs.existsSync(cfgPath)) {
    fs.writeFileSync(cfgPath, JSON.stringify({ testCommand: null, gate: { failOn: "orange" }, deprecated: [], customPatterns: [], rules: {} }, null, 2) + "\n");
  }
  const doc = await vscode.workspace.openTextDocument(cfgPath);
  vscode.window.showTextDocument(doc);
}

function cmdToggleScanMode(): void {
  const cur = settings().get("scanMode", "diff");
  const next = cur === "diff" ? "file" : "diff";
  settings().update("scanMode", next, vscode.ConfigurationTarget.Workspace);
  vscode.window.showInformationMessage(`DiffGate scan mode: ${next}`);
  reanalyzeOpen();
}

async function cmdRunGate(): Promise<void> {
  const editor = vscode.window.activeTextEditor;
  const folder = editor ? folderForUri(editor.document.uri) : vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (!folder) return;
  const config = getConfigFor(folder);
  if (!config.testCommand) {
    vscode.window.showWarningMessage('DiffGate: no "testCommand" set in .diffgate.json.');
    return;
  }
  const review = isGitRepo(folder) ? reviewChanges(folder, { mode: settings().get("diffMode", "working") }) : { files: [] as AnalyzeResult[] };
  await runGateForFolder(folder, config, review.files.flatMap((f) => f.findings));
}

// --- lifecycle ---------------------------------------------------------------
function reanalyzeOpen(): void {
  for (const editor of vscode.window.visibleTextEditors) analyzeDocument(editor.document);
}

export function activate(context: vscode.ExtensionContext): void {
  diagnostics = vscode.languages.createDiagnosticCollection("diffgate");
  aiChannel = vscode.window.createOutputChannel("DiffGate AI");
  gateChannel = vscode.window.createOutputChannel("DiffGate Gate");
  deepChannel = vscode.window.createOutputChannel("DiffGate Deep Review");

  statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBar.command = "diffgate.analyzeWorkspace";
  statusBar.text = "$(shield) DiffGate";
  statusBar.show();

  riskTree = new RiskTreeProvider();
  const treeView = vscode.window.createTreeView("diffgateRisk", { treeDataProvider: riskTree });

  const selector = { scheme: "file" };
  context.subscriptions.push(
    diagnostics, aiChannel, gateChannel, deepChannel, statusBar, treeView,
    vscode.languages.registerHoverProvider(selector, hoverProvider),
    vscode.languages.registerCodeActionsProvider(selector, codeActionProvider, { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }),
    vscode.commands.registerCommand("diffgate.analyzeWorkspace", () => { reanalyzeOpen(); refreshWorkspace(); vscode.commands.executeCommand("diffgateRisk.focus"); }),
    vscode.commands.registerCommand("diffgate.explainWithAI", cmdExplainWithAI),
    vscode.commands.registerCommand("diffgate.deepReview", cmdDeepReview),
    vscode.commands.registerCommand("diffgate.ignoreRule", cmdIgnoreRule),
    vscode.commands.registerCommand("diffgate.openConfig", cmdOpenConfig),
    vscode.commands.registerCommand("diffgate.toggleScanMode", cmdToggleScanMode),
    vscode.commands.registerCommand("diffgate.runGate", cmdRunGate)
  );

  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument((d) => analyzeDocument(d)),
    vscode.workspace.onDidChangeTextDocument((e) => debouncedAnalyze(e.document)),
    vscode.workspace.onDidSaveTextDocument((d) => { analyzeDocument(d); refreshWorkspace(); }),
    vscode.workspace.onDidCloseTextDocument((_d) => { /* keep diagnostics for tree */ }),
    vscode.window.onDidChangeActiveTextEditor((ed) => {
      if (!ed) return;
      const entry = findingsByUri.get(ed.document.uri.toString());
      if (entry) updateStatusBar(entry.res);
      else analyzeDocument(ed.document);
    }),
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration("diffgate")) { configCache.clear(); reanalyzeOpen(); refreshWorkspace(); }
    })
  );

  const cfgWatcher = vscode.workspace.createFileSystemWatcher("**/.diffgate.json");
  const onCfg = () => { configCache.clear(); reanalyzeOpen(); refreshWorkspace(); };
  cfgWatcher.onDidChange(onCfg);
  cfgWatcher.onDidCreate(onCfg);
  cfgWatcher.onDidDelete(onCfg);
  context.subscriptions.push(cfgWatcher);

  reanalyzeOpen();
  refreshWorkspace();
}

export function deactivate(): void {
  for (const t of debounceTimers.values()) clearTimeout(t);
}

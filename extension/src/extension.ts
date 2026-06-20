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
  overallTier,
  tierCounts,
  getGraph,
  attachImpact,
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
const gitFindingsByUri = new Map<string, AnalyzeResult>();
let decorationProvider: DiffGateFileDecorationProvider;
const configCache = new Map<string, Config>();
const debounceTimers = new Map<string, ReturnType<typeof setTimeout>>();
export const verdictCache = new Map<string, {
  verdict: string;
  verdictClass: "confirmed-risk" | "likely-safe" | "needs-human";
  steps: number;
  model: string;
  hitMax: boolean;
}>();

let orangeDecorationType: vscode.TextEditorDecorationType;
let yellowDecorationType: vscode.TextEditorDecorationType;
let greenDecorationType: vscode.TextEditorDecorationType;
let errorDecorationType: vscode.TextEditorDecorationType;
let codeLensProvider: DiffGateCodeLensProvider;
let inspectorProvider: DiffGateInspectorProvider;

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
  if (document && startLine < document.lineCount) {
    return document.lineAt(startLine).range;
  }
  const startCol = Math.max(0, finding.column ?? 0);
  const endCol = startCol + Math.max(1, (finding.code || "").length || 40);
  return new vscode.Range(startLine, startCol, startLine, endCol);
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
function collectAllResults(): AnalyzeResult[] {
  const all = new Map<string, AnalyzeResult>();
  for (const [uri, res] of gitFindingsByUri.entries()) {
    if (res.findings.length > 0) {
      all.set(uri, res);
    }
  }
  for (const [uri, entry] of findingsByUri.entries()) {
    if (entry.res.findings.length > 0) {
      all.set(uri, entry.res);
    } else {
      all.delete(uri);
    }
  }
  return Array.from(all.values());
}

function updateTreeData(): void {
  riskTree.setData(collectAllResults());
}

function analyzeDocument(document: vscode.TextDocument): void {
  if (!settings().get("enable", true)) return;
  if (document.uri.scheme !== "file") return;
  if (document.getText().length > MAX_BYTES) return;

  const folder = folderForUri(document.uri);
  const config = getConfigFor(folder);
  if (isIgnored(document.uri.fsPath, config, folder)) {
    diagnostics.delete(document.uri);
    findingsByUri.delete(document.uri.toString());
    updateTreeData();
    updateStatusBar();
    if (decorationProvider) {
      decorationProvider.fire();
    }
    return;
  }

  let res: AnalyzeResult;
  try {
    res = analyzeText(document.uri.fsPath, document.getText(), folder, config);
  } catch {
    return;
  }
  // Cross-file blast radius: only on saved files (never mid-edit — the graph indexes disk state),
  // and only when a code graph is present. No-op + zero subprocess cost otherwise.
  if (!document.isDirty) {
    try {
      const graph = getGraph(folder, config);
      if (graph) res = attachImpact([res], { cwd: folder, config, graph })[0];
    } catch {
      /* impact is best-effort */
    }
  }
  diagnostics.set(document.uri, res.findings.map((f) => toDiagnostic(f, document)));
  findingsByUri.set(document.uri.toString(), { res, folder, config });

  for (const editor of vscode.window.visibleTextEditors) {
    if (editor.document === document) {
      updateDecorations(editor);
    }
  }
  if (codeLensProvider) {
    codeLensProvider.fire();
  }

  for (const key of verdictCache.keys()) {
    if (key.startsWith(document.uri.toString() + "::")) verdictCache.delete(key);
  }

  updateTreeData();
  updateStatusBar();
  if (decorationProvider) {
    decorationProvider.fire();
  }

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
function updateStatusBar(): void {
  const results = collectAllResults();
  const allFindings = results.flatMap((res) => res.findings);
  const counts = tierCounts(allFindings);
  const maxTier = overallTier(allFindings);
  const totalGreen = counts.green;
  const totalYellow = counts.yellow;
  const totalOrange = counts.orange;

  const totalFindings = totalGreen + totalYellow + totalOrange;

  if (totalFindings === 0) {
    statusBar.text = "$(shield) DiffGate: clear";
    statusBar.tooltip = "No DiffGate findings across pending changes";
    statusBar.backgroundColor = undefined;
    statusBar.show();
    return;
  }

  statusBar.text = `$(shield) ${TIER_META[maxTier].icon} ${totalGreen}/${totalYellow}/${totalOrange}`;
  statusBar.tooltip = `DiffGate Workspace Total: ${totalOrange} orange · ${totalYellow} yellow · ${totalGreen} green — click to review all changes`;
  statusBar.backgroundColor =
    maxTier === "orange" ? new vscode.ThemeColor("statusBarItem.warningBackground") : undefined;
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
      const im = f.impact;
      if (im) {
        if (f.tierAdjusted === "deescalated") {
          md.appendMarkdown(`> $(arrow-down) **Blast radius:** no callers in the code graph — exported but unused _(down-tiered to review)_.\n\n`);
        } else if (im.callerCount > 0 || im.testGaps.length) {
          const fileCount = new Set(im.callers.map((r) => r.file).filter(Boolean)).size;
          const bits: string[] = [`**${im.callerCount}${im.truncated ? "+" : ""}** call site${im.callerCount === 1 ? "" : "s"}${fileCount ? ` across ${fileCount} file${fileCount === 1 ? "" : "s"}` : ""}`];
          if (im.reachable === true) bits.push("reachable from an entry point");
          if (im.reviewers.length) bits.push(`route: ${im.reviewers.slice(0, 3).map((r) => "@" + r).join(", ")}`);
          if (im.testGaps.length) bits.push(`$(warning) untested: ${im.testGaps.slice(0, 3).map((t) => t.symbol || t.file).join(", ")}`);
          const icon = f.tierAdjusted === "escalated" ? "$(flame)" : "$(zap)";
          md.appendMarkdown(`> ${icon} **Blast radius:** ${bits.join(" · ")}\n\n`);
        }
      }
      const vKey = `${document.uri.toString()}::${f.ruleId}::${f.line}`;
      const cached = verdictCache.get(vKey);
      if (cached) {
        let vc = cached.verdictClass;
        if (!vc) {
          const vLower = cached.verdict.toLowerCase();
          if (/confirmed.risk|exploitable|high.risk|critical/.test(vLower)) {
            vc = "confirmed-risk";
          } else if (/likely.safe|low.risk|no.exploit|benign/.test(vLower)) {
            vc = "likely-safe";
          } else {
            vc = "needs-human";
          }
        }
        let badge: string;
        if (vc === "confirmed-risk") {
          badge = "$(error) **Confirmed risk**";
        } else if (vc === "likely-safe") {
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

class DiffGateFileDecorationProvider implements vscode.FileDecorationProvider {
  private _onDidChangeFileDecorations = new vscode.EventEmitter<vscode.Uri | vscode.Uri[] | undefined>();
  readonly onDidChangeFileDecorations = this._onDidChangeFileDecorations.event;

  fire(uris?: vscode.Uri | vscode.Uri[]): void {
    this._onDidChangeFileDecorations.fire(uris);
  }

  provideFileDecoration(uri: vscode.Uri): vscode.ProviderResult<vscode.FileDecoration> {
    if (uri.scheme !== "file") return null;
    const uriStr = uri.toString();
    const entry = findingsByUri.get(uriStr);
    const gitRes = gitFindingsByUri.get(uriStr);
    const res = entry ? entry.res : gitRes;
    if (!res || res.findings.length === 0) return null;

    const tier = res.tier;
    if (tier === "orange") {
      return {
        badge: "DG",
        color: new vscode.ThemeColor("editorOverviewRuler.warningForeground"),
        tooltip: `DiffGate: ${res.counts.orange} orange (blocking) findings`,
      };
    } else if (tier === "yellow") {
      return {
        badge: "DG",
        color: new vscode.ThemeColor("editorOverviewRuler.infoForeground"),
        tooltip: `DiffGate: ${res.counts.yellow} yellow findings`,
      };
    } else if (tier === "green") {
      return {
        badge: "DG",
        color: new vscode.ThemeColor("editorOverviewRuler.addedForeground"),
        tooltip: `DiffGate: ${res.counts.green} green findings`,
      };
    }
    return null;
  }
}

// --- workspace review --------------------------------------------------------
function refreshWorkspace(): void {
  const folders = vscode.workspace.workspaceFolders || [];
  const diffMode = settings().get<string>("diffMode", "working");
  gitFindingsByUri.clear();
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
      const uri = vscode.Uri.file(fr.filePath);
      const uriStr = uri.toString();
      gitFindingsByUri.set(uriStr, fr);
      if (!findingsByUri.has(uriStr)) {
        diagnostics.set(uri, fr.findings.map((f) => toDiagnostic(f, null)));
        const config = getConfigFor(cwd);
        findingsByUri.set(uriStr, { res: fr, folder: cwd, config });
      }
    }
  }
  updateTreeData();
  updateStatusBar();
  if (decorationProvider) {
    decorationProvider.fire();
  }
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
    vscode.window.showInformationMessage(`DiffGate gate passed (${((r.durationMs ?? 0) / 1000).toFixed(1)}s).`);
  } else {
    vscode.window.showErrorMessage(`DiffGate gate FAILED (exit ${r.code}). See "DiffGate Gate" output.`);
  }
}

// --- commands ----------------------------------------------------------------
async function cmdExplainWithAI(uriStr: string, ruleId: string, line: number): Promise<void> {
  const entry = findingsByUri.get(uriStr);
  if (!entry) return;
  const f = entry.res.findings.find((x) => x.ruleId === ruleId && x.line === line);
  if (!f) return;
  if (!isAiAvailable(entry.config)) {
    vscode.window.showWarningMessage(`DiffGate AI is off. Enable diffgate.ai.enabled and set $${aiKeyEnv(entry.config)} (provider: ${describeProvider(entry.config)}).`);
    return;
  }
  let snippet = f.code;
  try {
    const doc = await vscode.workspace.openTextDocument(vscode.Uri.parse(uriStr));
    const lines = doc.getText().split("\n");
    snippet = lines.slice(Math.max(0, line - 5), line + 4).join("\n");
  } catch { /* fall back to f.code */ }
  
  if (inspectorProvider) {
    inspectorProvider.show(true);
    inspectorProvider.updateContent({
      type: "explain",
      title: f.title,
      ruleId: f.ruleId,
      file: path.basename(uriStr),
      line,
      status: "running"
    });
  }

  aiChannel.show(true);
  aiChannel.appendLine(`\n=== ${f.title} [${ruleId}] @ ${path.basename(uriStr)}:${line} ===`);
  await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: "DiffGate: asking Claude…" },
    async () => {
      try {
        const { text, model } = await explainFinding({ finding: f, snippet, language: entry.res.language, config: entry.config });
        aiChannel.appendLine(`[${model}]`);
        aiChannel.appendLine(text);
        if (inspectorProvider) {
          inspectorProvider.updateContent({
            type: "explain",
            title: f.title,
            ruleId: f.ruleId,
            file: path.basename(uriStr),
            line,
            status: "success",
            verdict: text,
            model
          });
        }
      } catch (e) {
        const errMsg = (e as Error).message;
        aiChannel.appendLine(`Error: ${errMsg}`);
        vscode.window.showErrorMessage(`DiffGate AI: ${errMsg}`);
        if (inspectorProvider) {
          inspectorProvider.updateContent({
            type: "explain",
            title: f.title,
            ruleId: f.ruleId,
            file: path.basename(uriStr),
            line,
            status: "error",
            error: errMsg
          });
        }
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
    vscode.window.showWarningMessage(`DiffGate AI is off. Enable diffgate.ai.enabled and set $${aiKeyEnv(entry.config)} (provider: ${describeProvider(entry.config)}).`);
    return;
  }
  let snippet = f.code;
  try {
    const doc = await vscode.workspace.openTextDocument(vscode.Uri.parse(uriStr));
    const lines = doc.getText().split("\n");
    snippet = lines.slice(Math.max(0, line - 5), line + 4).join("\n");
  } catch { /* fall back to f.code */ }

  const steps: { name: string; detail: string; status: "running" | "success" | "error" }[] = [];
  if (inspectorProvider) {
    inspectorProvider.show(true);
    inspectorProvider.updateContent({
      type: "deepReview",
      title: f.title,
      ruleId: f.ruleId,
      file: path.basename(uriStr),
      line,
      status: "running",
      steps
    });
  }

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
            if (steps.length > 0 && steps[steps.length - 1].status === "running") {
              steps[steps.length - 1].status = "success";
            }
            const summary = typeof input === "object" ? JSON.stringify(input).slice(0, 120) : String(input);
            steps.push({ name: `tool: ${name}`, detail: summary, status: "running" });
            
            if (inspectorProvider) {
              inspectorProvider.updateContent({
                type: "deepReview",
                title: f.title,
                ruleId: f.ruleId,
                file: path.basename(uriStr),
                line,
                status: "running",
                steps
              });
            }
            deepChannel.appendLine(`  [tool] ${name}(${summary})`);
            progress.report({ message: `tool: ${name}` });
          },
        });
        if (steps.length > 0) {
          steps[steps.length - 1].status = "success";
        }
        const cacheKey = `${uriStr}::${ruleId}::${line}`;
        verdictCache.set(cacheKey, {
          verdict: res.verdict,
          verdictClass: res.verdictClass,
          steps: res.steps,
          model: res.model,
          hitMax: res.hitMax
        });
        deepChannel.appendLine(`\n[model: ${res.model}  steps: ${res.steps}${res.hitMax ? " (step limit hit)" : ""}]`);
        deepChannel.appendLine(res.verdict);
        
        if (inspectorProvider) {
          inspectorProvider.updateContent({
            type: "deepReview",
            title: f.title,
            ruleId: f.ruleId,
            file: path.basename(uriStr),
            line,
            status: "success",
            steps,
            verdict: res.verdict,
            verdictClass: res.verdictClass,
            model: res.model
          });
        }

        if (res.hitMax) {
          vscode.window.showWarningMessage(`DiffGate Deep Review: reached step limit. See "DiffGate Deep Review" output.`);
        } else {
          vscode.window.showInformationMessage(`Deep Review complete — see "DiffGate Deep Review" output.`);
        }
      } catch (e) {
        if (steps.length > 0) {
          steps[steps.length - 1].status = "error";
        }
        const isAbort = (e as Error).name === "AbortError";
        const errorMsg = isAbort ? "Deep Review cancelled by user." : (e as Error).message;
        
        if (inspectorProvider) {
          inspectorProvider.updateContent({
            type: "deepReview",
            title: f.title,
            ruleId: f.ruleId,
            file: path.basename(uriStr),
            line,
            status: "error",
            steps,
            error: errorMsg
          });
        }

        if (isAbort) {
          deepChannel.appendLine("(cancelled)");
        } else {
          deepChannel.appendLine(`Error: ${errorMsg}`);
          vscode.window.showErrorMessage(`DiffGate Deep Review: ${errorMsg}`);
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

function updateDecorations(editor: vscode.TextEditor): void {
  if (!editor || editor.document.uri.scheme !== "file") return;
  const entry = findingsByUri.get(editor.document.uri.toString());
  if (!entry) {
    editor.setDecorations(errorDecorationType, []);
    editor.setDecorations(orangeDecorationType, []);
    editor.setDecorations(yellowDecorationType, []);
    editor.setDecorations(greenDecorationType, []);
    return;
  }

  const showInline = settings().get<boolean>("showInlineAnnotations", true);

  const errorDecorations: vscode.DecorationOptions[] = [];
  const orangeDecorations: vscode.DecorationOptions[] = [];
  const yellowDecorations: vscode.DecorationOptions[] = [];
  const greenDecorations: vscode.DecorationOptions[] = [];

  for (const f of entry.res.findings) {
    const range = buildRange(f, editor.document);
    const meta = TIER_META[f.tier];

    const decoration: vscode.DecorationOptions = {
      range,
      hoverMessage: new vscode.MarkdownString(`**${meta.icon} ${f.title}**  \`${f.ruleId}\`\n\n${f.message}`),
    };

    if (showInline && (f.blocking || f.tier === "orange" || f.tier === "yellow")) {
      decoration.renderOptions = {
        after: {
          contentText: `  |  ${meta.icon} DiffGate: ${f.title}`,
          color: new vscode.ThemeColor("descriptionForeground"),
          margin: "0 0 0 2em",
          fontStyle: "italic",
        }
      };
    }

    if (f.blocking) {
      errorDecorations.push(decoration);
    } else if (f.tier === "orange") {
      orangeDecorations.push(decoration);
    } else if (f.tier === "yellow") {
      yellowDecorations.push(decoration);
    } else {
      greenDecorations.push(decoration);
    }
  }

  editor.setDecorations(errorDecorationType, errorDecorations);
  editor.setDecorations(orangeDecorationType, orangeDecorations);
  editor.setDecorations(yellowDecorationType, yellowDecorations);
  editor.setDecorations(greenDecorationType, greenDecorations);
}

class DiffGateCodeLensProvider implements vscode.CodeLensProvider {
  private _onDidChangeCodeLenses = new vscode.EventEmitter<void>();
  readonly onDidChangeCodeLenses = this._onDidChangeCodeLenses.event;

  public fire(): void {
    this._onDidChangeCodeLenses.fire();
  }

  provideCodeLenses(document: vscode.TextDocument): vscode.CodeLens[] {
    const entry = findingsByUri.get(document.uri.toString());
    if (!entry) return [];
    const lenses: vscode.CodeLens[] = [];
    for (const f of entry.res.findings) {
      if (f.tier !== "orange") continue;
      const range = buildRange(f, document);
      
      const args = [document.uri.toString(), f.ruleId, f.line];
      const explainLens = new vscode.CodeLens(range, {
        title: "💡 Explain with AI",
        command: "diffgate.explainWithAI",
        arguments: args
      });
      lenses.push(explainLens);

      const deepLens = new vscode.CodeLens(range, {
        title: "🧪 Deep Review",
        command: "diffgate.deepReview",
        arguments: args
      });
      lenses.push(deepLens);
    }
    return lenses;
  }
}

function getNonce(): string {
  let text = "";
  const possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  for (let i = 0; i < 32; i++) {
    text += possible.charAt(Math.floor(Math.random() * possible.length));
  }
  return text;
}

class DiffGateInspectorProvider implements vscode.WebviewViewProvider {
  public static readonly viewType = "diffgateInspector";
  private _view?: vscode.WebviewView;
  private _isReady = false;
  private _pendingMessage?: any;

  resolveWebviewView(
    webviewView: vscode.WebviewView,
    context: vscode.WebviewViewResolveContext,
    token: vscode.CancellationToken
  ): void {
    this._view = webviewView;
    this._isReady = false;
    webviewView.webview.options = {
      enableScripts: true
    };
    webviewView.webview.html = this._getHtmlForWebview(webviewView.webview);
    webviewView.webview.onDidReceiveMessage((msg) => {
      if (msg.type === "ready") {
        this._isReady = true;
        if (this._pendingMessage) {
          webviewView.webview.postMessage(this._pendingMessage);
          this._pendingMessage = undefined;
        }
      }
    });
  }

  public show(preserveFocus = true): void {
    if (this._view) {
      this._view.show?.(preserveFocus);
    } else {
      vscode.commands.executeCommand("diffgateInspector.focus", { preserveFocus });
    }
  }

  public updateContent(data: {
    type: "explain" | "deepReview";
    title: string;
    ruleId: string;
    file: string;
    line: number;
    status: "idle" | "running" | "success" | "error";
    steps?: { name: string; detail: string; status: "running" | "success" | "error" }[];
    verdict?: string;
    verdictClass?: "confirmed-risk" | "likely-safe" | "needs-human";
    model?: string;
    error?: string;
  }): void {
    if (this._view && this._isReady) {
      this._view.webview.postMessage(data);
    } else {
      this._pendingMessage = data;
    }
  }

  private _getHtmlForWebview(webview: vscode.Webview): string {
    const nonce = getNonce();
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${webview.cspSource} 'unsafe-inline'; script-src 'nonce-${nonce}';">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DiffGate Inspector</title>
  <style>
    body {
      font-family: var(--vscode-font-family, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif);
      font-size: var(--vscode-font-size, 13px);
      color: var(--vscode-editor-foreground, #cccccc);
      background-color: var(--vscode-sideBar-background, #1e1e1e);
      padding: 12px;
      line-height: 1.5;
    }
    h2, h3, h4 {
      color: var(--vscode-titleBar-activeForeground, #ffffff);
      margin-top: 0;
      margin-bottom: 8px;
    }
    .header-card {
      background: var(--vscode-editor-background, #1e1e1e);
      border: 1px solid var(--vscode-widget-border, #3c3c3c);
      border-radius: 6px;
      padding: 12px;
      margin-bottom: 16px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.15);
    }
    .finding-title {
      font-size: 1.1em;
      font-weight: bold;
      color: var(--vscode-editorWarning-foreground, #e67e22);
    }
    .finding-meta {
      font-size: 0.9em;
      color: var(--vscode-descriptionForeground, #858585);
      margin-top: 4px;
    }
    .section-title {
      font-size: 0.9em;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: var(--vscode-descriptionForeground, #858585);
      border-bottom: 1px solid var(--vscode-panel-border, #3c3c3c);
      padding-bottom: 4px;
      margin-bottom: 12px;
      margin-top: 16px;
    }
    .stepper {
      display: flex;
      flex-direction: column;
      gap: 12px;
      margin-bottom: 16px;
    }
    .step-item {
      display: flex;
      gap: 10px;
      align-items: flex-start;
      padding: 6px 10px;
      border-radius: 4px;
      background: var(--vscode-welcomePage-tileBackground, #252526);
    }
    .step-icon {
      font-size: 1.2em;
    }
    .step-icon.running {
      animation: spin 1s linear infinite;
    }
    .step-content {
      flex: 1;
    }
    .step-name {
      font-weight: bold;
      color: var(--vscode-editor-foreground);
    }
    .step-detail {
      font-size: 0.9em;
      color: var(--vscode-descriptionForeground);
      margin-top: 2px;
      word-break: break-all;
    }
    .verdict-box {
      background: var(--vscode-editor-background, #1e1e1e);
      border-left: 4px solid var(--vscode-editorWarning-foreground, #e67e22);
      padding: 12px;
      border-radius: 0 6px 6px 0;
      white-space: pre-wrap;
      overflow-x: auto;
      font-family: var(--vscode-editor-font-family, Consolas, Monaco, monospace);
    }
    .verdict-box.success {
      border-left-color: var(--vscode-editorLightBulb-foreground, #2ecc71);
    }
    .verdict-box.error {
      border-left-color: var(--vscode-editorError-foreground, #e74c3c);
    }
    .empty-state {
      text-align: center;
      color: var(--vscode-descriptionForeground, #858585);
      margin-top: 40px;
      font-size: 1.1em;
    }
    .badge {
      display: inline-block;
      padding: 3px 6px;
      border-radius: 4px;
      font-size: 0.85em;
      font-weight: bold;
      margin-bottom: 8px;
    }
    .badge.running {
      background-color: var(--vscode-statusBar-debuggingBackground, #cc6633);
      color: #ffffff;
    }
    .badge.success {
      background-color: #28a745;
      color: #ffffff;
    }
    .badge.error {
      background-color: #dc3545;
      color: #ffffff;
    }
    .badge.confirmed {
      background-color: var(--vscode-editorError-foreground, #dc3545);
      color: #ffffff;
    }
    .badge.safe {
      background-color: var(--vscode-debugIcon-startForeground, #28a745);
      color: #ffffff;
    }
    .badge.review {
      background-color: var(--vscode-editorWarning-foreground, #e67e22);
      color: #ffffff;
    }
    @keyframes spin {
      0% { transform: rotate(0deg); }
      100% { transform: rotate(360deg); }
    }
  </style>
</head>
<body>
  <div id="welcome-view" class="empty-state">
    <p>Select a code finding in the editor and click <b>Explain with AI</b> or <b>Deep Review</b> to view analysis here.</p>
  </div>
  
  <div id="inspector-view" style="display: none;">
    <div class="header-card">
      <div id="finding-badge" class="badge"></div>
      <div id="finding-title" class="finding-title"></div>
      <div id="finding-meta" class="finding-meta"></div>
    </div>

    <div id="progress-section" style="display: none;">
      <div class="section-title">Deep Review Steps</div>
      <div id="stepper-list" class="stepper"></div>
    </div>

    <div id="verdict-section" style="display: none;">
      <div id="verdict-title" class="section-title">Verdict</div>
      <div id="verdict-box" class="verdict-box"></div>
      <div id="verdict-footer" class="finding-meta" style="margin-top: 8px;"></div>
    </div>
  </div>

  <script nonce="${nonce}">
    const vscode = acquireVsCodeApi();
    vscode.postMessage({ type: "ready" });
    const welcomeView = document.getElementById("welcome-view");
    const inspectorView = document.getElementById("inspector-view");
    const findingBadge = document.getElementById("finding-badge");
    const findingTitle = document.getElementById("finding-title");
    const findingMeta = document.getElementById("finding-meta");
    const progressSection = document.getElementById("progress-section");
    const stepperList = document.getElementById("stepper-list");
    const verdictSection = document.getElementById("verdict-section");
    const verdictTitle = document.getElementById("verdict-title");
    const verdictBox = document.getElementById("verdict-box");
    const verdictFooter = document.getElementById("verdict-footer");

    window.addEventListener("message", event => {
      const data = event.data;
      welcomeView.style.display = "none";
      inspectorView.style.display = "block";

      // 1. Update Header
      findingTitle.textContent = data.title;
      findingMeta.textContent = data.ruleId + " · " + data.file + ":" + data.line;

      // 2. Badge status
      findingBadge.className = "badge " + data.status;
      if (data.status === "running") {
        findingBadge.innerHTML = "⏳ Scanning...";
      } else if (data.status === "error") {
        findingBadge.innerHTML = "❌ Failed";
      } else {
        findingBadge.innerHTML = "✨ Complete";
      }

      // 3. Handle Explain vs Deep Review
      if (data.type === "explain") {
        progressSection.style.display = "none";
        if (data.status === "success") {
          verdictSection.style.display = "block";
          verdictTitle.textContent = "AI Explanation";
          verdictBox.className = "verdict-box success";
          verdictBox.textContent = data.verdict;
          verdictFooter.textContent = "Model: " + (data.model || "Unknown");
        } else if (data.status === "error") {
          verdictSection.style.display = "block";
          verdictTitle.textContent = "Error";
          verdictBox.className = "verdict-box error";
          verdictBox.textContent = data.error;
          verdictFooter.textContent = "";
        } else {
          verdictSection.style.display = "none";
        }
      } else if (data.type === "deepReview") {
        // Stepper progress
        progressSection.style.display = "block";
        stepperList.innerHTML = "";
        if (data.steps && data.steps.length > 0) {
          data.steps.forEach(step => {
            const item = document.createElement("div");
            item.className = "step-item";
            
            const icon = document.createElement("div");
            if (step.status === "running") {
              icon.className = "step-icon running";
              icon.textContent = "🔄";
            } else if (step.status === "error") {
              icon.className = "step-icon";
              icon.textContent = "❌";
            } else {
              icon.className = "step-icon";
              icon.textContent = "✅";
            }
            
            const content = document.createElement("div");
            content.className = "step-content";
            
            const name = document.createElement("div");
            name.className = "step-name";
            name.textContent = step.name;
            
            const detail = document.createElement("div");
            detail.className = "step-detail";
            detail.textContent = step.detail;
            
            content.appendChild(name);
            content.appendChild(detail);
            item.appendChild(icon);
            item.appendChild(content);
            stepperList.appendChild(item);
          });
        } else if (data.status === "running") {
          const item = document.createElement("div");
          item.className = "step-item";
          item.innerHTML = "<div class='step-icon running'>🔄</div><div class='step-content'><div class='step-name'>Starting Deep Review Agent...</div></div>";
          stepperList.appendChild(item);
        }

        // Final Verdict
        if (data.status === "success") {
          verdictSection.style.display = "block";
          verdictTitle.textContent = "Agent Critique & Verdict";
          verdictBox.textContent = data.verdict;
          verdictFooter.textContent = "Model: " + (data.model || "Unknown");

          // Visual verdict badge based on structured classification
          let vc = data.verdictClass;
          if (!vc) {
            const lowerV = (data.verdict || "").toLowerCase();
            if (/confirmed.risk|exploitable|high.risk|critical/.test(lowerV)) {
              vc = "confirmed-risk";
            } else if (/likely.safe|low.risk|no.exploit|benign/.test(lowerV)) {
              vc = "likely-safe";
            } else {
              vc = "needs-human";
            }
          }
          if (vc === "confirmed-risk") {
            findingBadge.className = "badge confirmed";
            findingBadge.innerHTML = "🔴 Confirmed Risk";
            verdictBox.className = "verdict-box error";
          } else if (vc === "likely-safe") {
            findingBadge.className = "badge safe";
            findingBadge.innerHTML = "🟢 Likely Safe";
            verdictBox.className = "verdict-box success";
          } else {
            findingBadge.className = "badge review";
            findingBadge.innerHTML = "🟡 Needs Review";
            verdictBox.className = "verdict-box";
          }
        } else if (data.status === "error") {
          verdictSection.style.display = "block";
          verdictTitle.textContent = "Agent Error";
          verdictBox.className = "verdict-box error";
          verdictBox.textContent = data.error;
          verdictFooter.textContent = "";
        } else {
          verdictSection.style.display = "none";
        }
      }
    });
  </script>
</body>
</html>`;
  }
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

  errorDecorationType = vscode.window.createTextEditorDecorationType({
    overviewRulerColor: new vscode.ThemeColor("editorOverviewRuler.errorForeground"),
    overviewRulerLane: vscode.OverviewRulerLane.Right,
    gutterIconPath: vscode.Uri.parse("data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxNiIgaGVpZ2h0PSIxNiIgdmlld0JveD0iMCAwIDE2IDE2Ij48Y2lyY2xlIGN4PSI4IiBjeT0iOCIgcj0iNC41IiBmaWxsPSIjZTc0YzNjIi8+PC9zdmc+"),
    gutterIconSize: "contain"
  });
  orangeDecorationType = vscode.window.createTextEditorDecorationType({
    overviewRulerColor: new vscode.ThemeColor("editorOverviewRuler.warningForeground"),
    overviewRulerLane: vscode.OverviewRulerLane.Right,
    gutterIconPath: vscode.Uri.parse("data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxNiIgaGVpZ2h0PSIxNiIgdmlld0JveD0iMCAwIDE2IDE2Ij48Y2lyY2xlIGN4PSI4IiBjeT0iOCIgcj0iNC41IiBmaWxsPSIjZDM1NDAwIi8+PC9zdmc+"),
    gutterIconSize: "contain"
  });
  yellowDecorationType = vscode.window.createTextEditorDecorationType({
    overviewRulerColor: new vscode.ThemeColor("editorOverviewRuler.infoForeground"),
    overviewRulerLane: vscode.OverviewRulerLane.Right,
    gutterIconPath: vscode.Uri.parse("data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxNiIgaGVpZ2h0PSIxNiIgdmlld0JveD0iMCAwIDE2IDE2Ij48Y2lyY2xlIGN4PSI4IiBjeT0iOCIgcj0iNC41IiBmaWxsPSIjZjFjNDBmIi8+PC9zdmc+"),
    gutterIconSize: "contain"
  });
  greenDecorationType = vscode.window.createTextEditorDecorationType({});

  decorationProvider = new DiffGateFileDecorationProvider();
  const fileDecReg = vscode.window.registerFileDecorationProvider(decorationProvider);

  statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBar.command = "diffgate.analyzeWorkspace";
  statusBar.text = "$(shield) DiffGate";
  statusBar.show();

  riskTree = new RiskTreeProvider();
  const treeView = vscode.window.createTreeView("diffgateRisk", { treeDataProvider: riskTree });

  inspectorProvider = new DiffGateInspectorProvider();
  const webviewViewReg = vscode.window.registerWebviewViewProvider(
    DiffGateInspectorProvider.viewType,
    inspectorProvider
  );

  codeLensProvider = new DiffGateCodeLensProvider();

  const selector = { scheme: "file" };
  context.subscriptions.push(
    diagnostics, aiChannel, gateChannel, deepChannel, statusBar, treeView,
    errorDecorationType, orangeDecorationType, yellowDecorationType, greenDecorationType,
    webviewViewReg, fileDecReg,
    vscode.languages.registerCodeLensProvider(selector, codeLensProvider),
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

  // Chat Participant registration
  if (typeof vscode.chat !== "undefined" && typeof vscode.chat.createChatParticipant === "function") {
    const handler: vscode.ChatRequestHandler = async (request, context, stream, token) => {
      const activeEditor = vscode.window.activeTextEditor;
      const userPrompt = request.prompt.trim().toLowerCase();

      if (userPrompt === "help" || userPrompt === "?") {
        stream.markdown("I am **DiffGate**, your diff-aware code review assistant. You can ask me:\n\n");
        stream.markdown("- **findings** or **scan**: to list all findings in the active file.\n");
        stream.markdown("- **summary**: to see a summary of risk counts in the active file.\n");
        stream.markdown("- **explain**: to explain any findings in the active file.\n");
        stream.markdown("- **rules**: to see information about DiffGate's rules.\n");
        return { metadata: { command: "help" } };
      }

      if (!activeEditor || activeEditor.document.uri.scheme !== "file") {
        stream.markdown("Please open a file in the editor first so I can inspect it for risk findings.");
        return;
      }

      const uriStr = activeEditor.document.uri.toString();
      const entry = findingsByUri.get(uriStr);

      if (userPrompt.includes("rule")) {
        stream.markdown("### DiffGate Built-in Rules\n\nDiffGate uses static AST analysis and pattern matching to classify risks into three tiers:\n\n");
        stream.markdown("- 🟠 **Orange (High-Impact/Gate)**: Hardcoded secrets, SQL injection, prototype pollution, CORS wildcards, public API signature changes, dangerous eval/execution.\n");
        stream.markdown("- 🟡 **Yellow (Review/Soft Dependency)**: Network calls, raw database queries, deprecated API usages, dynamic manifest dependency additions.\n");
        stream.markdown("- 🟢 **Green (Safe/Self-Contained)**: TODO markers, comments, logging statements.\n\n");
        stream.markdown("You can configure these rules in `.diffgate.json` at your project root.");
        return;
      }

      if (!entry || entry.res.findings.length === 0) {
        stream.markdown(`No findings found in **${path.basename(activeEditor.document.uri.fsPath)}** on changed lines. ✨ Everything looks clear!`);
        return;
      }

      const findings = entry.res.findings;
      const { green, yellow, orange } = entry.res.counts;

      if (userPrompt.includes("summary") || userPrompt.includes("count")) {
        stream.markdown(`### Findings Summary for \`${path.basename(activeEditor.document.uri.fsPath)}\`\n\n`);
        stream.markdown(`- 🟠 **Orange (High Risk):** ${orange}\n`);
        stream.markdown(`- 🟡 **Yellow (Medium Risk):** ${yellow}\n`);
        stream.markdown(`- 🟢 **Green (Safe/Info):** ${green}\n\n`);
        if (orange > 0) {
          stream.markdown(`⚠️ **Orange findings are blocking.** You must fix these before merging, or they will fail the verification gate.`);
        }
        return;
      }

      // Default: List findings and explain
      stream.markdown(`### 🛡️ DiffGate Findings in \`${path.basename(activeEditor.document.uri.fsPath)}\`:\n\n`);
      for (const f of findings) {
        const meta = TIER_META[f.tier];
        stream.markdown(`#### ${meta.icon} **L${f.line}**: ${f.title} (\`${f.ruleId}\`)\n`);
        stream.markdown(`> ${f.message}\n\n`);
        if (f.code) {
          stream.markdown(`\`\`\`${entry.res.language || ""}\n${f.code.trim()}\n\`\`\`\n\n`);
        }
        if (f.fix) {
          stream.markdown(`*Quick fix suggestion:* Replace with \`${f.fix.newText.trim()}\`\n\n`);
        }
      }
      return { metadata: { command: "list" } };
    };

    const participant = vscode.chat.createChatParticipant("diffgate-review.diffgate", handler);
    participant.iconPath = vscode.Uri.joinPath(context.extensionUri, "media", "shield.svg");
    context.subscriptions.push(participant);
  }

  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument((d) => analyzeDocument(d)),
    vscode.workspace.onDidChangeTextDocument((e) => debouncedAnalyze(e.document)),
    vscode.workspace.onDidSaveTextDocument((d) => { analyzeDocument(d); refreshWorkspace(); }),
    vscode.workspace.onDidCloseTextDocument((_d) => { /* keep diagnostics for tree */ }),
    vscode.window.onDidChangeActiveTextEditor((ed) => {
      if (!ed) return;
      updateDecorations(ed);
      const entry = findingsByUri.get(ed.document.uri.toString());
      if (!entry) analyzeDocument(ed.document);
      updateStatusBar();
    }),
    vscode.window.onDidChangeVisibleTextEditors((editors) => {
      for (const editor of editors) {
        updateDecorations(editor);
      }
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

  if (vscode.window.activeTextEditor) {
    updateDecorations(vscode.window.activeTextEditor);
  }
}

export function deactivate(): void {
  for (const t of debounceTimers.values()) clearTimeout(t);
}

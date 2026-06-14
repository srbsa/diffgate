// Smoke test for the bundled extension: stub the `vscode` module, load
// dist/extension.js, run activate(), then drive real code paths (document open
// -> diagnostics, hover, code actions). Catches runtime wiring bugs without a
// full VS Code instance.
const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const Module = require("module");

// --- minimal fake vscode -----------------------------------------------------
const captured = {
  commands: new Map(),
  open: [],
  change: [],
  save: [],
  config: [],
  messages: { warn: [], info: [], error: [] },
  hoverProvider: null,
  codeActionProvider: null,
  diags: new Map(),
};

class Position {
  constructor(line, character) {
    this.line = line;
    this.character = character;
  }
}
class Range {
  constructor(a, b, c, d) {
    if (a && typeof a === "object") {
      this.start = a;
      this.end = b;
    } else {
      this.start = new Position(a, b);
      this.end = new Position(c, d);
    }
  }
  get isEmpty() {
    return this.start.line === this.end.line && this.start.character === this.end.character;
  }
}
const settingsValues = { enable: true, scanMode: "diff", diffMode: "working", "ai.enabled": false, runGateOnSave: false };

const vscode = {
  Position,
  Range,
  Hover: class { constructor(c) { this.contents = c; } },
  MarkdownString: class {
    constructor(v) { this.value = v || ""; this.isTrusted = false; }
    appendMarkdown(s) { this.value += s; return this; }
  },
  Diagnostic: class { constructor(range, message, severity) { this.range = range; this.message = message; this.severity = severity; this.source = ""; } },
  DiagnosticSeverity: { Error: 0, Warning: 1, Information: 2, Hint: 3 },
  CodeAction: class { constructor(title, kind) { this.title = title; this.kind = kind; } },
  CodeActionKind: { QuickFix: "quickfix" },
  WorkspaceEdit: class { replace() {} },
  ThemeIcon: class { constructor(id, color) { this.id = id; this.color = color; } },
  ThemeColor: class { constructor(id) { this.id = id; } },
  TreeItem: class { constructor(label, collapsibleState) { this.label = label; this.collapsibleState = collapsibleState; } },
  TreeItemCollapsibleState: { None: 0, Collapsed: 1, Expanded: 2 },
  StatusBarAlignment: { Left: 1, Right: 2 },
  ProgressLocation: { Notification: 15, Window: 10 },
  ConfigurationTarget: { Workspace: 2 },
  EventEmitter: class {
    constructor() { this._fn = null; this.event = (fn) => { this._fn = fn; return { dispose() {} }; }; }
    fire(x) { if (this._fn) this._fn(x); }
  },
  Uri: {
    file: (p) => ({ scheme: "file", fsPath: p, toString: () => "file://" + p }),
    parse: (s) => ({ scheme: "file", fsPath: s.replace(/^file:\/\//, ""), toString: () => s }),
  },
  languages: {
    createDiagnosticCollection: () => ({
      set: (uri, d) => captured.diags.set(uri.toString(), d),
      delete: (uri) => captured.diags.delete(uri.toString()),
      dispose() {},
    }),
    registerHoverProvider: (_s, p) => { captured.hoverProvider = p; return { dispose() {} }; },
    registerCodeActionsProvider: (_s, p) => { captured.codeActionProvider = p; return { dispose() {} }; },
  },
  window: {
    activeTextEditor: undefined,
    visibleTextEditors: [],
    createOutputChannel: () => ({ appendLine() {}, show() {}, clear() {}, dispose() {} }),
    createStatusBarItem: () => ({ show() {}, hide() {}, dispose() {}, text: "", tooltip: "", backgroundColor: undefined, command: "" }),
    createTreeView: () => ({ dispose() {} }),
    showWarningMessage: (m) => { captured.messages.warn.push(m); return Promise.resolve(); },
    showInformationMessage: (m) => { captured.messages.info.push(m); return Promise.resolve(); },
    showErrorMessage: (m) => { captured.messages.error.push(m); return Promise.resolve(); },
    withProgress: (_o, task) => task(),
    onDidChangeActiveTextEditor: () => ({ dispose() {} }),
  },
  workspace: {
    workspaceFolders: [],
    getConfiguration: () => ({
      get: (k, d) => (settingsValues[k] !== undefined ? settingsValues[k] : d),
      update: (k, v) => { settingsValues[k] = v; return Promise.resolve(); },
    }),
    getWorkspaceFolder: () => ({ uri: { fsPath: captured.folder } }),
    onDidOpenTextDocument: (fn) => { captured.open.push(fn); return { dispose() {} }; },
    onDidChangeTextDocument: (fn) => { captured.change.push(fn); return { dispose() {} }; },
    onDidSaveTextDocument: (fn) => { captured.save.push(fn); return { dispose() {} }; },
    onDidCloseTextDocument: () => ({ dispose() {} }),
    onDidChangeConfiguration: (fn) => { captured.config.push(fn); return { dispose() {} }; },
    createFileSystemWatcher: () => ({ onDidChange() {}, onDidCreate() {}, onDidDelete() {}, dispose() {} }),
    asRelativePath: (p) => path.basename(p.fsPath || p),
    openTextDocument: () => Promise.resolve({ getText: () => "" }),
  },
  commands: {
    registerCommand: (name, fn) => { captured.commands.set(name, fn); return { dispose() {} }; },
    executeCommand: () => Promise.resolve(),
  },
};

// Inject the fake before loading the bundle.
const origLoad = Module._load;
Module._load = function (request, ...rest) {
  if (request === "vscode") return vscode;
  return origLoad.call(this, request, ...rest);
};

// --- fixture -----------------------------------------------------------------
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "grg-ext-"));
captured.folder = tmp;
const file = path.join(tmp, "pay.js");
const content = `export function processPayment(amount) {\n  const apiKey = "sk_live_abcdef0123456789abcd";\n  return StripeClient.charge(amount);\n}\n`;
fs.writeFileSync(file, content);

function makeDoc() {
  const lines = content.split("\n");
  return {
    uri: vscode.Uri.file(file),
    languageId: "javascript",
    lineCount: lines.length,
    getText: () => content,
    lineAt: (n) => ({ range: new Range(n, 0, n, (lines[n] || "").length) }),
    version: 1,
  };
}

// --- run ---------------------------------------------------------------------
const ext = require(path.join(__dirname, "..", "dist", "extension.js"));
const context = { subscriptions: [] };

ext.activate(context);
assert.ok(captured.open.length > 0, "should register an open handler");
assert.ok(captured.commands.has("guardrail.explainWithAI"), "should register AI command");
assert.ok(captured.commands.has("guardrail.toggleScanMode"), "should register toggle command");
assert.ok(captured.commands.has("guardrail.deepReview"), "should register deepReview command");

// Fire document open -> analysis -> diagnostics
const doc = makeDoc();
captured.open[0](doc);

const diags = captured.diags.get(doc.uri.toString());
assert.ok(diags && diags.length > 0, "expected diagnostics to be published");
const codes = diags.map((d) => d.code);
assert.ok(codes.includes("hardcoded-secret"), "expected hardcoded-secret diagnostic");
assert.ok(codes.includes("deprecated-api"), "expected deprecated-api diagnostic");
const secret = diags.find((d) => d.code === "hardcoded-secret");
assert.equal(secret.severity, vscode.DiagnosticSeverity.Error, "blocking secret -> Error severity");
assert.equal(secret.source, "guardrail");

// Hover on the secret line (line index 1)
const hover = captured.hoverProvider.provideHover(doc, new Position(1, 4));
assert.ok(hover && hover.contents.value.includes("Hardcoded secret"), "hover should describe the finding");
assert.ok(hover.contents.value.includes("Explain with AI"), "hover should offer AI explain");

// Code actions on the deprecated-api line (line index 2) -> should include a fix
const depDiag = diags.find((d) => d.code === "deprecated-api");
const depActions = captured.codeActionProvider.provideCodeActions(doc, depDiag.range, { diagnostics: [depDiag] });
assert.ok(depActions.some((a) => a.edit), "deprecated-api should offer a quick-fix edit");
assert.ok(depActions.some((a) => a.title.includes("Explain")), "should offer Explain action");

// Code actions on the secret (orange) -> should include Deep Review
const secretDiag = diags.find((d) => d.code === "hardcoded-secret");
const secretActions = captured.codeActionProvider.provideCodeActions(doc, secretDiag.range, { diagnostics: [secretDiag] });
assert.ok(secretActions.some((a) => a.title && a.title.includes("Deep Review")), "orange finding should offer Deep Review action");

// Hover on orange finding -> should have Deep Review link
const hoverOrange = captured.hoverProvider.provideHover(doc, new Position(1, 4));
assert.ok(hoverOrange.contents.value.includes("Deep Review"), "hover on orange finding should offer Deep Review link");

// Explain with AI when key absent -> warns gracefully
captured.commands.get("guardrail.explainWithAI")(doc.uri.toString(), "hardcoded-secret", 2);
// Deep Review with AI absent -> warns gracefully
captured.commands.get("guardrail.deepReview")(doc.uri.toString(), "hardcoded-secret", 2);
Promise.resolve().then(() => {
  assert.ok(captured.messages.warn.some((m) => /AI is off/i.test(m)), "should warn when AI unavailable");

  // Verdict cache: hover has no badge before deep review runs
  const hoverNoBadge = captured.hoverProvider.provideHover(doc, new Position(1, 4));
  assert.ok(hoverNoBadge, "hover should exist");
  const hasBadgeBefore = ["$(error)", "$(pass)", "$(question)"].some((b) => hoverNoBadge.contents.value.includes(b));
  assert.equal(hasBadgeBefore, false, "hover should NOT show a verdict badge before deep review runs");

  // Verdict cache: manually populate and verify badge appears in hover
  const docUri = doc.uri.toString();
  ext.verdictCache.set(`${docUri}::hardcoded-secret::2`, {
    verdict: "Confirmed risk — secret is used in an active payment call.",
    steps: 3,
    model: "test-model",
    hitMax: false,
  });
  const hoverWithBadge = captured.hoverProvider.provideHover(doc, new Position(1, 4));
  assert.ok(hoverWithBadge.contents.value.includes("$(error)"), "confirmed-risk verdict should show error badge");
  assert.ok(hoverWithBadge.contents.value.includes("Confirmed risk"), "verdict summary should appear in hover");
  ext.verdictCache.delete(`${docUri}::hardcoded-secret::2`);

  fs.rmSync(tmp, { recursive: true, force: true });
  Module._load = origLoad;
  console.log("✔ extension smoke test passed");
});

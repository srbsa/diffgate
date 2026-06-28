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
  codeLensProvider: null,
  activeEditor: [],
  visibleEditors: [],
  shownDocs: [],
  diags: new Map(),
  wsFolders: [],
  channels: {},
  inputPrompts: [],
  nextInput: "",
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
  CodeLens: class { constructor(range, command) { this.range = range; this.command = command; } },
  WorkspaceEdit: class { replace() {} },
  ThemeIcon: class { constructor(id, color) { this.id = id; this.color = color; } },
  ThemeColor: class { constructor(id) { this.id = id; } },
  TreeItem: class { constructor(label, collapsibleState) { this.label = label; this.collapsibleState = collapsibleState; } },
  TreeItemCollapsibleState: { None: 0, Collapsed: 1, Expanded: 2 },
  StatusBarAlignment: { Left: 1, Right: 2 },
  ProgressLocation: { Notification: 15, Window: 10 },
  ConfigurationTarget: { Workspace: 2 },
  OverviewRulerLane: { Left: 1, Center: 2, Right: 4, Full: 7 },
  EventEmitter: class {
    constructor() { this._fn = null; this.event = (fn) => { this._fn = fn; return { dispose() {} }; }; }
    fire(x) { if (this._fn) this._fn(x); }
  },
  Uri: {
    file: (p) => ({ scheme: "file", fsPath: p, toString: () => "file://" + p }),
    parse: (s) => ({ scheme: "file", fsPath: s.replace(/^file:\/\//, ""), toString: () => s }),
    joinPath: (base, ...parts) => {
      const fsPath = path.join(base.fsPath || "", ...parts);
      return { scheme: "file", fsPath, toString: () => "file://" + fsPath };
    },
  },
  languages: {
    createDiagnosticCollection: () => ({
      set: (uri, d) => captured.diags.set(uri.toString(), d),
      delete: (uri) => captured.diags.delete(uri.toString()),
      clear: () => captured.diags.clear(),
      dispose() {},
    }),
    registerHoverProvider: (_s, p) => { captured.hoverProvider = p; return { dispose() {} }; },
    registerCodeActionsProvider: (_s, p) => { captured.codeActionProvider = p; return { dispose() {} }; },
    registerCodeLensProvider: (_s, p) => { captured.codeLensProvider = p; return { dispose() {} }; },
  },
  window: {
    activeTextEditor: undefined,
    visibleTextEditors: [],
    createOutputChannel: (name) => {
      const rec = (captured.channels[name] = captured.channels[name] || { lines: [], shown: 0 });
      return { appendLine: (s) => rec.lines.push(s), show: () => { rec.shown++; }, clear: () => { rec.lines.length = 0; }, dispose() {} };
    },
    createStatusBarItem: () => ({ show() {}, hide() {}, dispose() {}, text: "", tooltip: "", backgroundColor: undefined, command: "" }),
    createTreeView: () => ({ dispose() {} }),
    showWarningMessage: (m) => { captured.messages.warn.push(m); return Promise.resolve(); },
    showInformationMessage: (m) => { captured.messages.info.push(m); return Promise.resolve(); },
    showErrorMessage: (m) => { captured.messages.error.push(m); return Promise.resolve(); },
    showTextDocument: (d) => { captured.shownDocs.push(d); return Promise.resolve(); },
    // Returns whatever the test sets in captured.nextInput (string = note, "" = skip, undefined = cancel).
    showInputBox: (_o) => { captured.inputPrompts.push(_o); return Promise.resolve(captured.nextInput); },
    withProgress: (_o, task) => task(),
    onDidChangeActiveTextEditor: (fn) => { captured.activeEditor.push(fn); return { dispose() {} }; },
    onDidChangeVisibleTextEditors: (fn) => { captured.visibleEditors.push(fn); return { dispose() {} }; },
    createTextEditorDecorationType: () => ({ id: Symbol("decoration"), dispose() {} }),
    registerWebviewViewProvider: () => ({ dispose() {} }),
    registerFileDecorationProvider: () => ({ dispose() {} }),
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
    onDidChangeWorkspaceFolders: (fn) => { captured.wsFolders.push(fn); return { dispose() {} }; },
    createFileSystemWatcher: () => ({ onDidChange() {}, onDidCreate() {}, onDidDelete() {}, dispose() {} }),
    asRelativePath: (p) => path.basename(p.fsPath || p),
    openTextDocument: () => Promise.resolve({ getText: () => "" }),
  },
  commands: {
    registerCommand: (name, fn) => { captured.commands.set(name, fn); return { dispose() {} }; },
    executeCommand: () => Promise.resolve(),
  },
  chat: {
    createChatParticipant: () => ({ iconPath: "", dispose() {} }),
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
const context = { subscriptions: [], extensionUri: vscode.Uri.file(path.join(__dirname, "..")) };

ext.activate(context);
assert.ok(captured.open.length > 0, "should register an open handler");
assert.ok(captured.commands.has("diffgate.explainWithAI"), "should register AI command");
assert.ok(captured.commands.has("diffgate.toggleScanMode"), "should register toggle command");
assert.ok(captured.commands.has("diffgate.deepReview"), "should register deepReview command");

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
assert.equal(secret.source, "diffgate");

// Hover on the secret line (line index 1)
const hover = captured.hoverProvider.provideHover(doc, new Position(1, 4));
assert.ok(hover && hover.contents.value.includes("Hardcoded secret"), "hover should describe the finding");
assert.ok(hover.contents.value.includes("Explain with AI"), "hover should offer AI explain");
assert.ok(hover.contents.value.includes("Confirmed"), "hover should surface the trust label on an orange finding");

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
captured.commands.get("diffgate.explainWithAI")(doc.uri.toString(), "hardcoded-secret", 2);
// Deep Review with AI absent -> warns gracefully
captured.commands.get("diffgate.deepReview")(doc.uri.toString(), "hardcoded-secret", 2);
Promise.resolve().then(async () => {
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

  runDecorationsScenario(doc);
  runCodeLensScenario(doc);
  runGuardScenario();
  await runCommandScenarios();
  runGateOnSaveScenario();
  runGitPruneScenario();
  runMultiRepoScenario();
  runEnableDisableScenario();
  await runDismissScenario();

  fs.rmSync(tmp, { recursive: true, force: true });
  // Dispose everything activate() registered — closes the .git fs.watch handles that would
  // otherwise keep the event loop alive and hang the test runner.
  for (const sub of context.subscriptions) { try { sub.dispose && sub.dispose(); } catch { /* ignore */ } }
  ext.deactivate();
  Module._load = origLoad;
  console.log("✔ extension smoke test passed");
}).catch((e) => { console.error(e); process.exit(1); });

// --- decorations: gutter + inline annotations for the analyzed document --------------------------
function runDecorationsScenario(doc) {
  assert.ok(captured.activeEditor.length > 0, "should register an active-editor handler");
  const editor = {
    document: doc,
    decorations: [],
    setDecorations(type, opts) { this.decorations.push({ type, opts }); },
  };
  // The handler calls updateDecorations(editor): one setDecorations per tier bucket.
  captured.activeEditor[0](editor);
  assert.ok(editor.decorations.length >= 4, "decorations applied across tier buckets");
  const totalOpts = editor.decorations.reduce((n, d) => n + d.opts.length, 0);
  const findingCount = diags.length; // diagnostics were published from the same finding set
  assert.equal(totalOpts, findingCount, "every published finding is rendered as a decoration");
  const hasInline = editor.decorations.some((d) => d.opts.some((o) => o.renderOptions && o.renderOptions.after));
  assert.ok(hasInline, "the blocking secret gets an inline end-of-line annotation");
}

// --- code lens: only orange findings get a "Deep Review" lens ------------------------------------
function runCodeLensScenario(doc) {
  assert.ok(captured.codeLensProvider, "a code lens provider should be registered");
  const lenses = captured.codeLensProvider.provideCodeLenses(doc);
  assert.ok(Array.isArray(lenses) && lenses.length > 0, "orange finding yields at least one code lens");

  const emptyDoc = {
    uri: vscode.Uri.file(path.join(tmp, "no-findings.js")),
    getText: () => "", lineCount: 0,
    lineAt: () => ({ range: new Range(0, 0, 0, 0) }),
  };
  assert.deepEqual(captured.codeLensProvider.provideCodeLenses(emptyDoc), [], "no findings → no lenses");
}

// --- guards: analyzeDocument must skip non-file schemes and oversized files ----------------------
function runGuardScenario() {
  const secret = `const apiKey = "sk_live_abcdef0123456789abcd";`;
  // A git diff view (scheme "git") or output channel must never be analyzed.
  const gitDoc = {
    uri: { scheme: "git", fsPath: "/x/pay.js", toString: () => "git:/x/pay.js" },
    languageId: "javascript", lineCount: 1, getText: () => secret,
    lineAt: () => ({ range: new Range(0, 0, 0, secret.length) }), version: 1,
  };
  captured.open[0](gitDoc);
  assert.ok(!captured.diags.has("git:/x/pay.js"), "non-file scheme document is not analyzed");

  // A file over the 2MB cap is skipped to keep typing responsive — even though it holds a secret.
  const huge = secret + "\n" + "x".repeat(2 * 1024 * 1024);
  const bigUri = vscode.Uri.file(path.join(tmp, "big.js"));
  const bigDoc = {
    uri: bigUri, languageId: "javascript", lineCount: 2, getText: () => huge,
    lineAt: () => ({ range: new Range(0, 0, 0, secret.length) }), version: 1,
  };
  captured.open[0](bigDoc);
  assert.ok(!captured.diags.has(bigUri.toString()), "files over the size cap are skipped");
}

// --- commands: toggle scan mode, ignore rule, open config ----------------------------------------
async function runCommandScenarios() {
  assert.equal(settingsValues.scanMode, "diff");
  captured.commands.get("diffgate.toggleScanMode")();
  assert.equal(settingsValues.scanMode, "file", "toggle flips diff -> file");
  assert.ok(captured.messages.info.some((m) => /scan mode: file/i.test(m)), "announces the new mode");
  captured.commands.get("diffgate.toggleScanMode")(); // restore for any later assertions
  assert.equal(settingsValues.scanMode, "diff");

  // A stray Command-Palette invocation (no args) must be a safe no-op, never a thrown path.join.
  assert.doesNotThrow(() => captured.commands.get("diffgate.ignoreRule")(), "ignoreRule with no args must not throw");
  assert.doesNotThrow(() => captured.commands.get("diffgate.explainWithAI")(), "explainWithAI with no args must not throw");
  assert.doesNotThrow(() => captured.commands.get("diffgate.deepReview")(), "deepReview with no args must not throw");

  // ignoreRule writes the disable into .diffgate.json without clobbering existing keys.
  const folder = fs.mkdtempSync(path.join(os.tmpdir(), "grg-ext-ignore-"));
  fs.writeFileSync(path.join(folder, ".diffgate.json"), JSON.stringify({ testCommand: "npm test" }) + "\n");
  captured.commands.get("diffgate.ignoreRule")(folder, "deprecated-api");
  const cfg = JSON.parse(fs.readFileSync(path.join(folder, ".diffgate.json"), "utf-8"));
  assert.equal(cfg.rules["deprecated-api"], false, "rule disabled in config");
  assert.equal(cfg.testCommand, "npm test", "existing config keys preserved");
  fs.rmSync(folder, { recursive: true, force: true });

  // openConfig scaffolds a default .diffgate.json when none exists and opens it.
  const cfgFolder = fs.mkdtempSync(path.join(os.tmpdir(), "grg-ext-cfg-"));
  vscode.workspace.workspaceFolders = [{ uri: vscode.Uri.file(cfgFolder) }];
  const before = captured.shownDocs.length;
  await captured.commands.get("diffgate.openConfig")();
  assert.ok(fs.existsSync(path.join(cfgFolder, ".diffgate.json")), "openConfig scaffolds a config file");
  assert.ok(captured.shownDocs.length > before, "openConfig opens the file in an editor");
  fs.rmSync(cfgFolder, { recursive: true, force: true });
}

// --- runGateOnSave: the verification gate must fire ONLY on a real save, not on open/keystroke ----
// Regression guard for the flag firing from the shared analyzeDocument path (which also runs on
// open and on every debounced edit). With the flag on and an orange finding present, opening or
// typing must NOT spawn the project's testCommand; only saving may.
function runGateOnSaveScenario() {
  const folder = fs.mkdtempSync(path.join(os.tmpdir(), "grg-ext-gate-"));
  fs.writeFileSync(path.join(folder, ".diffgate.json"),
    JSON.stringify({ testCommand: "exit 0", gate: { failOn: "orange" } }) + "\n");
  const gfile = path.join(folder, "gate.js");
  const code = `const apiKey = "sk_live_abcdef0123456789abcd";\n`;
  fs.writeFileSync(gfile, code);
  const lines = code.split("\n");
  const gdoc = {
    uri: vscode.Uri.file(gfile), languageId: "javascript", lineCount: lines.length,
    getText: () => code, lineAt: (n) => ({ range: new Range(n, 0, n, (lines[n] || "").length) }),
    isDirty: false, version: 1,
  };

  // Resolve config + diff base to this folder (folderForUri falls back to the workspace folder).
  vscode.workspace.workspaceFolders = [{ uri: vscode.Uri.file(folder) }];
  captured.folder = folder;
  settingsValues.runGateOnSave = true;
  const gate = () => captured.channels["DiffGate Gate"] || { lines: [], shown: 0 };
  const before = gate().lines.length;

  // Open / debounced-change path (runGate not requested) → gate must NOT fire.
  captured.open[0](gdoc);
  assert.equal(gate().lines.length, before, "opening a file must not trigger the verification gate");

  // Save path (runGate: true) → gate fires (testCommand is echoed to the gate channel synchronously).
  captured.save[0](gdoc);
  assert.ok(gate().lines.some((l) => /exit 0/.test(l)), "saving with an orange finding triggers the gate");

  settingsValues.runGateOnSave = false;
  fs.rmSync(folder, { recursive: true, force: true });
}

// --- enable flag: diffgate.enable=false must clear and stop ALL findings -------------------------
// Regression guard for the flag being a no-op on the sidebar/git path: previously only the
// per-document analyzer respected `enable`, so refreshWorkspace + the config watcher kept
// republishing diagnostics. Toggling the flag off must wipe every surface.
function runEnableDisableScenario() {
  // Seed a diagnostic via the workspace path so there is something to clear.
  const repo = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "grg-ext-enable-")));
  const { execFileSync } = require("child_process");
  const g = (args) => execFileSync("git", args, { cwd: repo, stdio: "pipe" });
  g(["init", "-q"]); g(["config", "user.email", "t@e.com"]); g(["config", "user.name", "t"]); g(["config", "commit.gpgsign", "false"]);
  fs.writeFileSync(path.join(repo, "x.js"), "export const ok = 1;\n");
  g(["add", "."]); g(["commit", "-q", "-m", "base"]);
  fs.writeFileSync(path.join(repo, "x.js"), `const apiKey = "sk_live_abcdef0123456789abcd";\n`);

  vscode.workspace.workspaceFolders = [{ uri: vscode.Uri.file(repo) }];
  captured.folder = repo;
  settingsValues.enable = true;
  captured.wsFolders[0]({ added: [], removed: [] });
  assert.ok(captured.diags.size > 0, "a finding is published while enabled");

  // Flip the flag off and fire the configuration-change handler.
  settingsValues.enable = false;
  assert.ok(captured.config.length > 0, "a configuration-change handler is registered");
  captured.config[0]({ affectsConfiguration: () => true });
  assert.equal(captured.diags.size, 0, "disabling diffgate.enable clears every published diagnostic");

  // And while disabled, a workspace refresh must not repopulate.
  captured.wsFolders[0]({ added: [], removed: [] });
  assert.equal(captured.diags.size, 0, "no findings are republished while disabled");

  settingsValues.enable = true;
  fs.rmSync(repo, { recursive: true, force: true });
}

// --- dismiss / confirm: recording a verdict writes .diffgate/learnings.json and suppresses the finding
// Covers the editor half of `diffgate feedback`: dismiss removes the exact pattern on re-analysis,
// the note prompt is cancellable (Esc records nothing), confirm flips the verdict, and a no-arg
// Command-Palette invocation is a safe no-op.
async function runDismissScenario() {
  const folder = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "grg-ext-dismiss-")));
  const dcontent = `const apiKey = "sk_live_abcdef0123456789abcd";\n`;
  const dfile = path.join(folder, "pay.js");
  fs.writeFileSync(dfile, dcontent);
  const dlines = dcontent.split("\n");
  const ddoc = {
    uri: vscode.Uri.file(dfile), languageId: "javascript", lineCount: dlines.length,
    getText: () => dcontent, lineAt: (n) => ({ range: new Range(n, 0, n, (dlines[n] || "").length) }),
    isDirty: false, version: 1,
  };
  vscode.workspace.workspaceFolders = [{ uri: vscode.Uri.file(folder) }];
  captured.folder = folder;

  assert.ok(captured.commands.has("diffgate.dismissFinding"), "dismissFinding command registered");
  assert.ok(captured.commands.has("diffgate.confirmFinding"), "confirmFinding command registered");

  // Open -> the secret is flagged.
  const dUri = ddoc.uri.toString();
  const storePath = path.join(folder, ".diffgate", "learnings.json");
  captured.open[0](ddoc);
  let d = captured.diags.get(dUri);
  assert.ok(d && d.some((x) => x.code === "hardcoded-secret"), "secret should be flagged before any verdict");

  // Cancelling the note prompt (Esc -> undefined) records nothing — no store file is created.
  captured.nextInput = undefined;
  await captured.commands.get("diffgate.dismissFinding")(dUri, "hardcoded-secret", 1);
  assert.ok(!fs.existsSync(storePath), "cancelling the note prompt records nothing");

  // Confirm: records a verdict but does NOT suppress (it feeds the signal ratio, not the gate).
  captured.nextInput = "";
  await captured.commands.get("diffgate.confirmFinding")(dUri, "hardcoded-secret", 1);
  let store = JSON.parse(fs.readFileSync(storePath, "utf-8"));
  assert.ok(store.entries.some((e) => e.ruleId === "hardcoded-secret" && e.verdict === "confirm"),
    "a confirm verdict is recorded");
  captured.open[0](ddoc);
  d = captured.diags.get(dUri);
  assert.ok(d && d.some((x) => x.code === "hardcoded-secret"), "a confirmed finding is still reported");

  // Dismiss: flips the verdict for the same pattern (latest per ruleId+codeHash wins) and suppresses it.
  captured.nextInput = "";
  await captured.commands.get("diffgate.dismissFinding")(dUri, "hardcoded-secret", 1);
  store = JSON.parse(fs.readFileSync(storePath, "utf-8"));
  assert.ok(store.entries.some((e) => e.ruleId === "hardcoded-secret" && e.verdict === "dismiss"),
    "dismiss replaces the confirm verdict");

  // Re-analyze -> the dismissed pattern is gone (the learnings cache was invalidated on record).
  captured.open[0](ddoc);
  d = captured.diags.get(dUri);
  assert.ok(!d || !d.some((x) => x.code === "hardcoded-secret"),
    "the dismissed finding is suppressed on the next analysis");

  // No-arg invocation (stray Command-Palette use) is a safe no-op.
  captured.nextInput = "";
  await assert.doesNotReject(async () => captured.commands.get("diffgate.dismissFinding")(),
    "dismissFinding with no args must not throw");

  captured.nextInput = "";
  fs.rmSync(folder, { recursive: true, force: true });
}

// --- multi-repo: a workspace folder containing several nested git repos analyzes ALL of them ------
// Regression guard for the nested-repo discovery fix (a multi-repo workspace previously showed only
// the first repo). Drives discoverRepos -> scanForRepos -> refreshWorkspace against real git repos.
function runMultiRepoScenario() {
  const { execFileSync } = require("child_process");
  const parent = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "grg-ext-multi-")));
  const dirty = `export function ok() {\n  const apiKey = "sk_live_abcdef0123456789abcd";\n  return 1;\n}\n`;
  const expectUris = [];
  for (const name of ["repoA", "repoB"]) {
    const repo = path.join(parent, name);
    fs.mkdirSync(repo);
    const g = (args) => execFileSync("git", args, { cwd: repo, stdio: "pipe" });
    g(["init", "-q"]);
    g(["config", "user.email", "t@example.com"]);
    g(["config", "user.name", "t"]);
    g(["config", "commit.gpgsign", "false"]);
    const f = path.join(repo, "svc.js");
    fs.writeFileSync(f, "export function ok() {\n  return 1;\n}\n"); // clean baseline
    g(["add", "."]);
    g(["commit", "-q", "-m", "base"]);
    fs.writeFileSync(f, dirty); // uncommitted secret -> enters the working-tree diff
    expectUris.push(vscode.Uri.file(f).toString());
  }

  vscode.workspace.workspaceFolders = [{ uri: vscode.Uri.file(parent) }];
  captured.folder = parent;
  captured.wsFolders[0]({ added: [], removed: [] });

  for (const uri of expectUris) {
    const d = captured.diags.get(uri);
    assert.ok(d && d.some((x) => x.code === "hardcoded-secret"),
      `nested repo file must be discovered and analyzed: ${uri}`);
  }

  fs.rmSync(parent, { recursive: true, force: true });
}

// --- regression: sidebar/diagnostics clear after a commit removes a file from the diff -----------
// Reproduces the reported bug: refreshWorkspace() must prune findings for files that have left the
// working-tree diff (committed/reverted). Drives the real save + workspace-folders handlers against
// a real git repo. The first activate() ran with workspaceFolders=[], so no fs.watch exists yet;
// we point workspaceFolders at the git repo and reuse the captured handlers (no dangling watcher).
function runGitPruneScenario() {
  const { execFileSync } = require("child_process");
  // realpath so the editor-URI path matches git's `--show-toplevel` (which resolves the
  // /var -> /private/var symlink on macOS); real repos under /Users are not symlinked.
  const gitTmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "grg-ext-git-")));
  const g = (args) => execFileSync("git", args, { cwd: gitTmp, stdio: "pipe" });
  g(["init", "-q"]);
  g(["config", "user.email", "t@example.com"]);
  g(["config", "user.name", "t"]);
  g(["config", "commit.gpgsign", "false"]);

  const gfile = path.join(gitTmp, "svc.js");
  // Clean baseline (no findings), committed.
  fs.writeFileSync(gfile, "export function ok() {\n  return 1;\n}\n");
  g(["add", "."]);
  g(["commit", "-q", "-m", "base"]);

  // Introduce a secret in the working tree -> now in the diff.
  const dirty = `export function ok() {\n  const apiKey = "sk_live_abcdef0123456789abcd";\n  return 1;\n}\n`;
  fs.writeFileSync(gfile, dirty);

  // Point the (already-registered) handlers at the git repo.
  vscode.workspace.workspaceFolders = [{ uri: vscode.Uri.file(gitTmp) }];
  captured.folder = gitTmp;

  const gLines = dirty.split("\n");
  const gdoc = {
    uri: vscode.Uri.file(gfile),
    languageId: "javascript",
    lineCount: gLines.length,
    getText: () => dirty,
    lineAt: (n) => ({ range: new Range(n, 0, n, (gLines[n] || "").length) }),
    isDirty: false,
    version: 1,
  };

  // Save handler: analyzeDocument + refreshWorkspace -> finding enters sidebar/diagnostics.
  captured.save[0](gdoc);
  const gUri = gdoc.uri.toString();
  const before = captured.diags.get(gUri);
  assert.ok(before && before.some((d) => d.code === "hardcoded-secret"),
    "uncommitted secret should be published as a diagnostic");

  // Commit the change: working tree now matches HEAD -> file leaves the diff.
  g(["add", "."]);
  g(["commit", "-q", "-m", "add secret"]);

  // Trigger refreshWorkspace WITHOUT re-analyzing the doc (isolates the prune path).
  assert.ok(captured.wsFolders.length > 0, "should register a workspace-folders handler");
  captured.wsFolders[0]({ added: [], removed: [] });

  assert.ok(!captured.diags.has(gUri),
    "committed file must be pruned from diagnostics after it leaves the diff");

  fs.rmSync(gitTmp, { recursive: true, force: true });
}

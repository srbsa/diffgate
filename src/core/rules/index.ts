import path from "path";
import { matchesPathScope } from "../config.js";
import { walk } from "../parsers/javascript.js";
import { hasAstSupport } from "../parsers/index.js";
import { compileTsQuery } from "../parsers/treesitter.js";
import { BUILTIN_RULES, deprecatedRules, customPatternRules, legacyOrangeRules, RULE_PACKS } from "./builtin.js";
import { dependencyRelevantLines } from "./manifests.js";
import type { Rule, FileRule, PatternRule, AstRule, TsAstRule, RuleContext, EmitFn, Finding, FindingEmitArg, AstNode, TsNode, TsTree, Config } from "../types.js";

// Docs/prose files are effectively all-comment: code-shaped rules misfire on prose (the word
// "oauth2-provider" in a changelog tripped auth-crypto — hyphen is a \b boundary). On these files
// only rules that opt into raw comment scanning (`scanRaw`) run — exactly the rules whose hits are
// still real in prose (a secret pasted in a README leaks, a TODO in docs is a marker).
const DOCS_FILE = /\.(?:md|mdx|markdown|txt|rst|adoc)$/i;
// .txt files that are machine-read, not prose — they must keep full rule coverage
// (requirements.txt drives dependency-manifest; CMakeLists.txt is code).
const NON_DOC_TXT = /^(?:requirements[\w.-]*|constraints[\w.-]*|cmakelists)\.txt$/i;

const DEPENDENCY_MANIFESTS = new Set([
  "package.json", "requirements.txt", "pyproject.toml", "go.mod",
  "gemfile", "pom.xml", "build.gradle", "build.gradle.kts", "cargo.toml", "composer.json",
]);

const FILE_RULES: FileRule[] = [
  {
    id: "migration-file",
    type: "file",
    tier: "orange",
    title: "Database migration file",
    message: "Migration file changed. Verify it is reversible, ordered correctly, and safe to run on production data.",
    detect(ctx: RuleContext, emit: EmitFn) {
      if (/(^|[\/\\])migrations?[\/\\]/i.test(ctx.filePath) || /\.migration\.[a-z]+$/i.test(ctx.filePath)) {
        emit({});
      }
    },
  },
  {
    id: "dependency-manifest",
    type: "file",
    tier: "yellow",
    title: "Dependency manifest change",
    message: "A dependency manifest changed. Review added/updated/removed packages for license, bundle size, and supply-chain risk.",
    detect(ctx: RuleContext, emit: EmitFn) {
      const base = path.basename(ctx.filePath).toLowerCase();
      if (!DEPENDENCY_MANIFESTS.has(base)) return;
      // Only fire when a *dependency* line changed — a version bump, scripts edit, or other
      // metadata churn in the manifest is not a supply-chain event (release commits were
      // tripping this on every bump). No diff info (new file) keeps the old fire-always path.
      if (!ctx.changedLines) { emit({}); return; }
      const relevant = dependencyRelevantLines(base, ctx.lines);
      if (!relevant) { emit({}); return; }
      const hit = [...ctx.changedLines].filter((n) => relevant[n - 1]).sort((a, b) => a - b)[0];
      if (hit) emit({ line: hit });
    },
  },
];

function ruleAppliesToLanguage(rule: Rule, language: string): boolean {
  if (rule.excludeLanguages?.includes(language)) return false;
  const langs = rule.languages || ["*"];
  return langs.includes("*") || langs.includes(language);
}

/** A rule as exposed to agents via the MCP `diffgate://rules` resource — metadata only, no matcher. */
export interface RuleCatalogEntry {
  id: string;
  type: Rule["type"];
  tier: string;
  blocking: boolean;
  title: string;
  /** Human/agent-readable guidance. Empty when the rule's message is computed per match. */
  description: string;
  languages: string[];
  /** The rule pack this belongs to (web-security / compatibility / hygiene), or null. */
  pack: string | null;
}

// Enumerate effective rules across representative languages so language-scoped rules (e.g. an
// AST rule that only applies to javascript) are not omitted from the catalog. Union by id.
const CATALOG_LANGUAGES = ["javascript", "typescript", "python", "go", "ruby", "java", "csharp", "kotlin", "rust", "php", "*"];

/** Active rule catalog for this repo's resolved config — reflects tier/enabled overrides and packs. */
export function ruleCatalog(config: Partial<Config>): RuleCatalogEntry[] {
  const packOf = (id: string): string | null => {
    for (const [pack, ids] of Object.entries(RULE_PACKS)) if (ids.includes(id)) return pack;
    return null;
  };
  const byId = new Map<string, RuleCatalogEntry>();
  for (const lang of CATALOG_LANGUAGES) {
    for (const rule of getRules(config, lang)) {
      if (byId.has(rule.id)) continue;
      byId.set(rule.id, {
        id: rule.id,
        type: rule.type,
        tier: rule.tier,
        blocking: !!rule.blocking,
        title: rule.title,
        description: typeof rule.message === "string" ? rule.message : "",
        languages: rule.languages || ["*"],
        pack: packOf(rule.id),
      });
    }
  }
  return [...byId.values()].sort((a, b) => a.id.localeCompare(b.id));
}

export function getRules(config: Partial<Config>, language: string): Rule[] {
  const all: Rule[] = [
    ...BUILTIN_RULES,
    ...FILE_RULES,
    ...deprecatedRules(config),
    ...customPatternRules(config),
    ...legacyOrangeRules(config),
  ];
  const overrides = (config && config.rules) || {};

  // Find disabled/enabled packs. Driven by RULE_PACKS itself so a newly added pack is honored
  // without touching this list.
  const disabledPacks = new Set<string>();
  const enabledPacks = new Set<string>();
  for (const [key, value] of Object.entries(overrides)) {
    if (!Object.prototype.hasOwnProperty.call(RULE_PACKS, key)) continue;
    const v = value as unknown;
    if (v === false) disabledPacks.add(key);
    // `"pack": true` (or `{enabled:true}`) opts a default-off pack in wholesale, so a family that
    // ships opt-in doesn't need one override line per rule.
    else if (v === true || (v && typeof v === "object" && (v as { enabled?: boolean }).enabled)) {
      enabledPacks.add(key);
    }
  }
  const inEnabledPack = (id: string): boolean => {
    for (const pack of enabledPacks) {
      const ids = RULE_PACKS[pack];
      if (ids && ids.includes(id)) return true;
    }
    return false;
  };

  const out: Rule[] = [];
  for (const rule of all) {
    // Check if rule belongs to a disabled pack
    let inDisabledPack = false;
    for (const pack of disabledPacks) {
      const packRules = RULE_PACKS[pack];
      if (packRules && packRules.includes(rule.id)) {
        // If the rule itself is explicitly overridden to true or an object, do not disable it
        if (overrides[rule.id] === undefined) {
          inDisabledPack = true;
          break;
        }
      }
    }
    if (inDisabledPack) continue;

    const ov = overrides[rule.id];
    if (ov === false) continue;
    // `rules: { "<id>": true }` opts a default-off rule in, mirroring `false` turning one off.
    // Without this, the boolean form was asymmetric: `false` disabled a rule but `true` was a silent
    // no-op, so a config that looked like it enabled `single-caller-abstraction` or
    // `reinvented-helper` quietly did nothing and the user saw an unexplained absence of findings.
    if (
      rule.enabledByDefault === false &&
      ov !== true &&
      !(ov && (ov as { enabled?: boolean }).enabled) &&
      !inEnabledPack(rule.id)
    ) continue;
    if (!ruleAppliesToLanguage(rule, language)) continue;
    if (rule.skipIfAst && hasAstSupport(language)) continue;

    let effective = rule;
    if (ov && typeof ov === "object") {
      const ovObj = ov as { enabled?: boolean; tier?: string; blocking?: boolean; include?: string[]; exclude?: string[] };
      if (ovObj.enabled === false) continue;
      if (ovObj.tier || ovObj.blocking !== undefined || ovObj.include || ovObj.exclude) {
        effective = {
          ...rule,
          tier: (ovObj.tier as Rule["tier"]) || rule.tier,
          blocking: ovObj.blocking ?? rule.blocking,
          include: Array.isArray(ovObj.include) ? ovObj.include : rule.include,
          exclude: Array.isArray(ovObj.exclude) ? ovObj.exclude : rule.exclude,
        };
      }
    }
    out.push(effective);
  }
  return out;
}

function makeFinding(rule: Rule, fields: FindingEmitArg & { line: number }): Finding {
  return {
    ruleId: rule.id,
    tier: fields.tier || rule.tier,
    blocking: fields.blocking ?? !!rule.blocking,
    title: rule.title,
    message: fields.message || (typeof rule.message === "string" ? rule.message : ""),
    line: fields.line,
    column: fields.column ?? 0,
    endLine: fields.endLine ?? fields.line,
    endColumn: fields.endColumn ?? fields.column ?? 0,
    code: fields.code || "",
    fix: fields.fix || null,
    symbol: fields.symbol ?? null,
    tierAdjusted: fields.tierAdjusted,
    meta: fields.meta,
  };
}

function firstChangedLine(ctx: RuleContext): number {
  if (ctx.changedLines && ctx.changedLines.size > 0) {
    return Math.min(...ctx.changedLines);
  }
  return 1;
}

function inChange(ctx: RuleContext, line: number): boolean {
  return !ctx.changedLines || ctx.changedLines.has(line);
}

function runPattern(rule: PatternRule, ctx: RuleContext, findings: Finding[]): void {
  // Match against comment-masked text so commented-out code is not flagged — except rules where a
  // comment hit is still real (secrets, todo markers), which opt into raw scanning.
  const scan = rule.scanRaw ? ctx.lines : (ctx.scanLines ?? ctx.lines);
  for (let i = 0; i < ctx.lines.length; i++) {
    const lineNo = i + 1;
    if (!inChange(ctx, lineNo)) continue;
    const text = scan[i];
    if (!text) continue;
    const realText = ctx.lines[i] ?? text;
    for (const re of rule.patterns) {
      const m = re.exec(text);
      if (m) {
        let message = typeof rule.message === "function" ? rule.message(m[0]) : (rule.message || "");
        let tier: Finding["tier"] | undefined;
        if (rule.validate) {
          const v = rule.validate(m[0]);
          if (v && v.skip) continue; // false positive — try the next pattern on this line
          if (v && v.tier) tier = v.tier;
          if (v && v.note) message = message ? `${message} (${v.note})` : v.note;
        }
        findings.push(
          makeFinding(rule, {
            line: lineNo,
            column: m.index,
            endLine: lineNo,
            endColumn: m.index + m[0].length,
            code: realText.trim(),
            message,
            tier,
          })
        );
        break;
      }
    }
  }
}

function runFile(rule: FileRule, ctx: RuleContext, findings: Finding[]): void {
  // Honor the diff gate: a tracked file with an empty changed-line set is *in scope* but has
  // no pending change, so file-level rules (dependency-manifest, migration-file) must stay quiet —
  // otherwise they linger on an unchanged file. `null` means "no diff info" (new/untracked file or
  // whole-file mode), where firing is correct. Mirrors `inChange` for pattern/ast rules.
  if (ctx.changedLines && ctx.changedLines.size === 0) return;
  rule.detect(ctx, (partial: FindingEmitArg) => {
    const line = partial.line || firstChangedLine(ctx);
    const text = ctx.lines[line - 1] || "";
    findings.push(
      makeFinding(rule, {
        line,
        column: 0,
        endLine: line,
        endColumn: text.length,
        code: text.trim(),
        message: partial.message,
        tier: partial.tier,
        meta: partial.meta,
      })
    );
  });
}

function runAst(rule: AstRule, ast: AstNode, ctx: RuleContext, findings: Finding[]): void {
  walk(ast, (node: AstNode, parent: AstNode | null) => {
    rule.visit(node, parent, ctx, (arg: FindingEmitArg) => {
      const loc = arg && arg.loc;
      if (!loc || !loc.start) return;
      const line = loc.start.line;
      if (!inChange(ctx, line)) return;
      const text = ctx.lines[line - 1] || "";
      findings.push(
        makeFinding(rule, {
          line,
          column: loc.start.column,
          endLine: loc.end ? loc.end.line : line,
          endColumn: loc.end ? loc.end.column : loc.start.column,
          code: text.trim(),
          message: arg.message,
          tier: arg.tier,
          blocking: arg.blocking,
          tierAdjusted: arg.tierAdjusted,
          fix: arg.fix,
          symbol: arg.symbol,
          meta: arg.meta,
        })
      );
    });
  });
}

/** Apply a `tsast` rule's visitor over a tree-sitter tree. When the rule declares a `sinkQuery`, run
 *  it once and visit only the captured sink nodes; otherwise walk every named node. Mirrors runAst.
 *  Findings are position-sorted downstream (analyzer), so visit order does not affect output. */
function runTsAst(rule: TsAstRule, tree: TsTree, ctx: RuleContext, findings: Finding[]): void {
  const emit = (arg: FindingEmitArg): void => {
    const loc = arg && arg.loc;
    if (!loc || !loc.start) return;
    const line = loc.start.line;
    if (!inChange(ctx, line)) return;
    const text = ctx.lines[line - 1] || "";
    findings.push(
      makeFinding(rule, {
        line,
        column: loc.start.column,
        endLine: loc.end ? loc.end.line : line,
        endColumn: loc.end ? loc.end.column : loc.start.column,
        code: arg.code || text.trim(),
        message: arg.message,
        tier: arg.tier,
        blocking: arg.blocking,
        tierAdjusted: arg.tierAdjusted,
        fix: arg.fix,
        symbol: arg.symbol,
        meta: arg.meta,
      })
    );
  };

  if (rule.sinkQuery) {
    const query = compileTsQuery(ctx.language, rule.sinkQuery);
    if (query) {
      const seen = new Set<number>(); // a node can be captured by multiple patterns — visit it once
      for (const m of query.matches(tree.rootNode)) {
        for (const cap of m.captures) {
          if (seen.has(cap.node.id)) continue;
          seen.add(cap.node.id);
          rule.visit(cap.node, ctx, emit);
        }
      }
      return;
    }
    // query failed to compile for this grammar → fall through to the full walk (graceful)
  }

  const visit = (node: TsNode): void => {
    rule.visit(node, ctx, emit);
    for (let i = 0; i < node.namedChildCount; i++) {
      const child = node.namedChild(i);
      if (child) visit(child);
    }
  };
  visit(tree.rootNode);
}

export function runRules({ ast, ctx, config }: { ast: AstNode | null; ctx: RuleContext; config: Partial<Config> }): Finding[] {
  const findings: Finding[] = [];
  const tsTree = ctx.tsTree ?? null;
  const rules = getRules(config, ctx.language);
  const isDocs = DOCS_FILE.test(ctx.filePath) && !NON_DOC_TXT.test(path.basename(ctx.filePath));
  for (const rule of rules) {
    if (isDocs && !rule.scanRaw) continue;
    // Per-rule path scoping (CustomPattern / rules-override include/exclude). Enforced here, the
    // single funnel every surface analyzes through, so CLI/MCP/editor agree on where a rule runs.
    if ((rule.include || rule.exclude) && !matchesPathScope(ctx.filePath, rule)) continue;
    // A loaded tree-sitter tree owns precision for this language: skip the broad cross-language
    // regex candidates (`skipIfAst`) so the precise `tsast` rule isn't doubled by a noisy regex.
    // `skipIfAstLangs` is the per-language form — skip only when the tree is for a language that has a
    // precise replacement (e.g. dangerous-exec defers to PHP's AST exec rules but stays on for Python).
    // When no tree is present (grammar not loaded) the regex still fires — recall is preserved.
    if (rule.type === "pattern" && tsTree && (rule.skipIfAst || (rule.skipIfAstLangs?.includes(ctx.language)))) continue;
    if (rule.type === "pattern") runPattern(rule, ctx, findings);
    else if (rule.type === "file") runFile(rule, ctx, findings);
    else if (rule.type === "ast" && ast) runAst(rule, ast, ctx, findings);
    else if (rule.type === "tsast" && tsTree) runTsAst(rule, tsTree, ctx, findings);
  }
  return findings;
}

export { FILE_RULES };

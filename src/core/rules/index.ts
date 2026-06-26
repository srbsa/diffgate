import path from "path";
import { walk } from "../parsers/javascript.js";
import { hasAstSupport } from "../parsers/index.js";
import { BUILTIN_RULES, deprecatedRules, customPatternRules, legacyOrangeRules, RULE_PACKS } from "./builtin.js";
import type { Rule, FileRule, PatternRule, AstRule, RuleContext, EmitFn, Finding, FindingEmitArg, AstNode, Config } from "../types.js";

const DEPENDENCY_MANIFESTS = new Set([
  "package.json", "requirements.txt", "pyproject.toml", "go.mod",
  "gemfile", "pom.xml", "build.gradle", "cargo.toml", "composer.json",
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
      if (DEPENDENCY_MANIFESTS.has(base)) emit({});
    },
  },
];

function ruleAppliesToLanguage(rule: Rule, language: string): boolean {
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
const CATALOG_LANGUAGES = ["javascript", "typescript", "python", "go", "ruby", "java", "rust", "php", "*"];

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

  // Find disabled packs
  const disabledPacks = new Set<string>();
  for (const [key, value] of Object.entries(overrides)) {
    if (value === false && (key === "web-security" || key === "compatibility" || key === "hygiene")) {
      disabledPacks.add(key);
    }
  }

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
    if (rule.enabledByDefault === false && !(ov && (ov as { enabled?: boolean }).enabled)) continue;
    if (!ruleAppliesToLanguage(rule, language)) continue;
    if (rule.skipIfAst && hasAstSupport(language)) continue;

    let effective = rule;
    if (ov && typeof ov === "object") {
      const ovObj = ov as { enabled?: boolean; tier?: string; blocking?: boolean };
      if (ovObj.enabled === false) continue;
      if (ovObj.tier || ovObj.blocking !== undefined) {
        effective = { ...rule, tier: (ovObj.tier as Rule["tier"]) || rule.tier, blocking: ovObj.blocking ?? rule.blocking };
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
        })
      );
    });
  });
}

export function runRules({ ast, ctx, config }: { ast: AstNode | null; ctx: RuleContext; config: Partial<Config> }): Finding[] {
  const findings: Finding[] = [];
  const rules = getRules(config, ctx.language);
  for (const rule of rules) {
    if (rule.type === "pattern") runPattern(rule, ctx, findings);
    else if (rule.type === "file") runFile(rule, ctx, findings);
    else if (rule.type === "ast" && ast) runAst(rule, ast, ctx, findings);
  }
  return findings;
}

export { FILE_RULES };

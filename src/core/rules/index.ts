import path from "path";
import { walk } from "../parsers/javascript.js";
import { hasAstSupport } from "../parsers/index.js";
import { BUILTIN_RULES, deprecatedRules, customPatternRules, legacyOrangeRules } from "./builtin.js";
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

export function getRules(config: Partial<Config>, language: string): Rule[] {
  const all: Rule[] = [
    ...BUILTIN_RULES,
    ...FILE_RULES,
    ...deprecatedRules(config),
    ...customPatternRules(config),
    ...legacyOrangeRules(config),
  ];
  const overrides = (config && config.rules) || {};
  const out: Rule[] = [];
  for (const rule of all) {
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
    blocking: !!rule.blocking,
    title: rule.title,
    message: fields.message || (typeof rule.message === "string" ? rule.message : ""),
    line: fields.line,
    column: fields.column ?? 0,
    endLine: fields.endLine ?? fields.line,
    endColumn: fields.endColumn ?? fields.column ?? 0,
    code: fields.code || "",
    fix: fields.fix || null,
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
  for (let i = 0; i < ctx.lines.length; i++) {
    const lineNo = i + 1;
    if (!inChange(ctx, lineNo)) continue;
    const text = ctx.lines[i];
    if (!text) continue;
    for (const re of rule.patterns) {
      const m = re.exec(text);
      if (m) {
        const message = typeof rule.message === "function" ? rule.message(m[0]) : (rule.message || "");
        findings.push(
          makeFinding(rule, {
            line: lineNo,
            column: m.index,
            endLine: lineNo,
            endColumn: m.index + m[0].length,
            code: text.trim(),
            message,
          })
        );
        break;
      }
    }
  }
}

function runFile(rule: FileRule, ctx: RuleContext, findings: Finding[]): void {
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
          fix: arg.fix,
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

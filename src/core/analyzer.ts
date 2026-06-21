import { detectLanguage, hasAstSupport } from "./parsers/index.js";
import { parseJs } from "./parsers/javascript.js";
import { maskComments } from "./mask.js";
import { applyTestScope } from "./testscope.js";
import { runRules } from "./rules/index.js";
import { overallTier, tierCounts, TIER_ORDER } from "./tiers.js";
import { collectExportedSignatures } from "./signatures.js";
import type { Finding, AnalyzeResult, RuleContext, Config, AstNode } from "./types.js";

function detectSignatureDrift(prevContent: string, language: string, currentAst: AstNode, ctx: RuleContext, findings: Finding[]): void {
  let prevAst: AstNode;
  try {
    prevAst = parseJs(prevContent, language);
  } catch {
    return;
  }
  const prev = collectExportedSignatures(prevAst);
  const cur = collectExportedSignatures(currentAst);
  for (const [name, curSig] of cur) {
    const prevSig = prev.get(name);
    if (!prevSig) continue;
    const before = prevSig.params.join(", ");
    const after = curSig.params.join(", ");
    if (before === after) continue;
    const line = curSig.loc.start.line;
    if (ctx.changedLines && !ctx.changedLines.has(line)) continue;
    findings.push({
      ruleId: "signature-drift",
      tier: "orange",
      blocking: false,
      title: "Exported signature changed",
      message: `Signature of exported \`${name}\` changed: (${before}) → (${after}). Existing callers may break — update call sites or keep it backward-compatible.`,
      line,
      column: curSig.loc.start.column,
      endLine: curSig.loc.end ? curSig.loc.end.line : line,
      endColumn: curSig.loc.end ? curSig.loc.end.column : curSig.loc.start.column,
      code: (ctx.lines[line - 1] || "").trim(),
      fix: null,
      symbol: name,
    });
  }
}

function dedupe(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const out: Finding[] = [];
  for (const f of findings) {
    const key = `${f.ruleId}:${f.line}:${f.column}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(f);
  }
  return out;
}

export function analyze({ filePath, content, previousContent = null, changedLines = null, config = {} }: {
  filePath: string;
  content: string;
  previousContent?: string | null;
  changedLines?: Set<number> | null;
  config?: Partial<Config>;
}): AnalyzeResult {
  const language = detectLanguage(filePath);
  const lines = content.split("\n");

  let ast: AstNode | null = null;
  let parseError: string | null = null;
  if (hasAstSupport(language)) {
    try {
      ast = parseJs(content, language);
    } catch (e) {
      parseError = (e as Error).message;
    }
  }

  const scanLines = maskComments(lines, language);
  const ctx: RuleContext = { filePath, language, lines, scanLines, changedLines, config: config as Config, ast };

  const findings = runRules({ ast, ctx, config });

  if (ast && previousContent && hasAstSupport(language)) {
    try {
      detectSignatureDrift(previousContent, language, ast, ctx, findings);
    } catch {
      /* drift detection is best-effort */
    }
  }

  const scoped = applyTestScope(findings, filePath, config);

  const deduped = dedupe(scoped).sort(
    (a, b) =>
      a.line - b.line ||
      (TIER_ORDER[b.tier] ?? 0) - (TIER_ORDER[a.tier] ?? 0) ||
      a.ruleId.localeCompare(b.ruleId)
  );

  return {
    filePath,
    language,
    findings: deduped,
    tier: overallTier(deduped),
    counts: tierCounts(deduped),
    blocking: deduped.some((f) => f.blocking),
    parseError,
  };
}

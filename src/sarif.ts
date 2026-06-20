import path from "path";
import type { AnalyzeResult, Finding } from "./core/types.js";

const SARIF_LEVEL: Record<string, string> = { orange: "error", yellow: "warning", green: "note" };

function impactProps(f: Finding): Record<string, unknown> | undefined {
  if (!f.impact && !f.symbol && !f.tierAdjusted && !f.security) return undefined;
  const props: Record<string, unknown> = {};
  if (f.symbol) props["symbol"] = f.symbol;
  if (f.tierAdjusted) props["tierAdjusted"] = f.tierAdjusted;
  if (f.impact) {
    props["callerCount"] = f.impact.callerCount;
    if (f.impact.reviewers.length) props["suggestedReviewers"] = f.impact.reviewers;
    if (f.impact.testGaps.length) props["testGaps"] = f.impact.testGaps.map((t) => t.symbol || t.file);
    if (f.impact.reachable !== null) props["reachable"] = f.impact.reachable;
    if (typeof f.impact.complexity === "number") props["complexity"] = f.impact.complexity;
    if (f.impact.staleDoc) props["staleDoc"] = true;
    props["impactSource"] = f.impact.source;
  }
  if (f.security) {
    props["tainted"] = f.security.tainted;
    if (f.security.dataFlow.length) props["dataFlow"] = f.security.dataFlow.map((r) => r.symbol || r.file);
    props["securitySource"] = f.security.source;
  }
  return props;
}

export function toSarif(files: AnalyzeResult[], cwd: string, version = "0.0.0"): string {
  const rulesMap = new Map<string, { id: string; shortDescription: { text: string } }>();
  const results = [];

  for (const f of files) {
    const relPath = path.relative(cwd, f.filePath);
    for (const finding of f.findings) {
      if (!rulesMap.has(finding.ruleId)) {
        rulesMap.set(finding.ruleId, {
          id: finding.ruleId,
          shortDescription: { text: finding.title },
        });
      }

      const props = impactProps(finding);
      results.push({
        ruleId: finding.ruleId,
        level: SARIF_LEVEL[finding.tier] || "warning",
        message: {
          text: finding.message,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: relPath,
                uriBaseId: "%SRCROOT%",
              },
              region: {
                startLine: finding.line,
                startColumn: finding.column + 1, // 1-indexed in SARIF
                endLine: finding.endLine || finding.line,
                endColumn: (finding.endColumn || finding.column) + 1,
              },
            },
          },
        ],
        ...(props ? { properties: props } : {}),
      });
    }
  }

  const sarif = {
    $schema: "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "DiffGate",
            version,
            rules: Array.from(rulesMap.values()),
          },
        },
        results,
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}

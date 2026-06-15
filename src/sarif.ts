import path from "path";
import type { AnalyzeResult } from "./core/types.js";

export function toSarif(files: AnalyzeResult[], cwd: string): string {
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

      results.push({
        ruleId: finding.ruleId,
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
            version: "0.1.1",
            rules: Array.from(rulesMap.values()),
          },
        },
        results,
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}

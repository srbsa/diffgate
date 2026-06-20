// SOC 2 control mapping. The orange gate is an auditable change-management control
// (CC8.1: changes are reviewed/approved before deployment). Each rule maps to the
// Trust Services Criteria it provides evidence for, so a review run doubles as audit
// evidence. Full narrative in COMPLIANCE.md. This is a mapping, not a legal attestation.
import type { AnalyzeResult, Finding } from "./core/types.js";

export interface Control {
  id: string;
  title: string;
}

export const CONTROLS: Record<string, Control> = {
  "CC6.1": { id: "CC6.1", title: "Logical access — restrict access to data and systems" },
  "CC6.6": { id: "CC6.6", title: "Protect against threats from outside the system boundary" },
  "CC6.7": { id: "CC6.7", title: "Restrict the transmission/movement of sensitive data" },
  "CC6.8": { id: "CC6.8", title: "Prevent or detect unauthorized/malicious software" },
  "CC7.1": { id: "CC7.1", title: "Detect and monitor for vulnerabilities and misconfigurations" },
  "CC8.1": { id: "CC8.1", title: "Changes are authorized, designed, tested, and approved before deployment" },
};

/** ruleId -> SOC 2 controls it provides evidence for. */
export const RULE_CONTROLS: Record<string, string[]> = {
  "hardcoded-secret": ["CC6.1", "CC6.7"],
  "db-schema-destructive": ["CC8.1", "CC7.1"],
  "db-schema-change": ["CC8.1"],
  "migration-file": ["CC8.1"],
  "sql-injection": ["CC6.6", "CC7.1"],
  "nosql-injection": ["CC6.6", "CC7.1"],
  "xss-sink": ["CC6.6", "CC7.1"],
  "path-traversal": ["CC6.6", "CC7.1"],
  "prototype-pollution": ["CC6.6", "CC7.1"],
  "permissive-cors": ["CC6.6"],
  "auth-crypto": ["CC6.1"],
  "dangerous-exec": ["CC6.8", "CC7.1"],
  "public-api-change": ["CC8.1"],
  "signature-drift": ["CC8.1"],
  "dependency-manifest": ["CC6.8", "CC7.1"],
  "deprecated-api": ["CC8.1"],
};

export interface ControlEvidence {
  control: Control;
  rules: string[];
  findings: number;
}

export interface ComplianceReport {
  /** Controls with at least one finding in this review. */
  evidence: ControlEvidence[];
  /** Rules that fired but aren't mapped to a control (informational). */
  unmapped: string[];
  totalFindings: number;
  blocked: boolean;
}

export function complianceReport(files: AnalyzeResult[]): ComplianceReport {
  const byControl = new Map<string, { rules: Set<string>; findings: number }>();
  const unmapped = new Set<string>();
  let total = 0;
  let blocked = false;
  const findings: Finding[] = files.flatMap((f) => f.findings);

  for (const f of findings) {
    total += 1;
    if (f.blocking) blocked = true;
    const controls = RULE_CONTROLS[f.ruleId];
    if (!controls || controls.length === 0) {
      unmapped.add(f.ruleId);
      continue;
    }
    for (const cid of controls) {
      const cur = byControl.get(cid) || { rules: new Set<string>(), findings: 0 };
      cur.rules.add(f.ruleId);
      cur.findings += 1;
      byControl.set(cid, cur);
    }
  }

  const evidence: ControlEvidence[] = [...byControl.entries()]
    .map(([cid, v]) => ({ control: CONTROLS[cid], rules: [...v.rules].sort(), findings: v.findings }))
    .sort((a, b) => a.control.id.localeCompare(b.control.id));

  return { evidence, unmapped: [...unmapped].sort(), totalFindings: total, blocked };
}

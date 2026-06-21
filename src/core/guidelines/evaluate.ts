import { complete, isAiAvailable } from "../llm/index.js";
import { resolveGuidelinesForFile } from "./resolve.js";
import { TIER_ORDER } from "../tiers.js";
import type { Config, Finding, FetchFn, Tier, GuidelineRuleSet } from "../types.js";

export interface GuidelineFileInput {
  filePath: string;
  rel: string;
  language: string;
  content: string;
  changedLines: number[] | null;
}

export interface GuidelineEvalInput {
  root: string;
  config: Config;
  files: GuidelineFileInput[];
  signal?: AbortSignal;
  fetchImpl?: FetchFn;
  log?: (msg: string) => void;
}

interface Hunk {
  rel: string;
  code: string;
}

export interface GuidelineGroupPayload {
  sources: string[];
  guidelines: string;
  hunks: Hunk[];
}

export interface GuidelinePayload {
  groups: GuidelineGroupPayload[];
  instructions: string;
  schema: Record<string, unknown>;
  /** Host mode = the calling agent judges its own diff. This is a self-review, NOT an independent
   *  gate, so it is always advisory: the host must never block a change on these results. */
  independent: false;
  advisory: true;
}

export type GuidelineEvalResult =
  | { mode: "model"; findings: Finding[] }
  | { mode: "host"; payload: GuidelinePayload };

const SYSTEM =
  "You are a senior code reviewer enforcing a team's written coding guidelines against a diff. " +
  "Only flag changed lines that concretely violate a stated guideline. Do NOT invent rules, restate the guidelines, " +
  "or flag style the guidelines don't mention. If nothing violates, return an empty list. Be terse.";

const RESULT_SCHEMA = {
  type: "array",
  items: {
    type: "object",
    required: ["file", "line", "title", "message"],
    properties: {
      file: { type: "string", description: "repo-relative path from the provided hunks" },
      line: { type: "number" },
      title: { type: "string", description: "short rule name, e.g. 'missing retry on payments call'" },
      message: { type: "string", description: "what's violated and the concrete fix" },
      severity: { type: "string", enum: ["info", "warn", "error"] },
    },
  },
};

function instructions(): string {
  return (
    "For each hunk, check the changed code against the guidelines that apply to it. " +
    "Return ONLY a JSON array matching the schema; no prose. Empty array if there are no violations."
  );
}

/** Compact, line-numbered snippet of the changed lines (+/- a little context), capped. */
function buildSnippet(content: string, changedLines: number[] | null, max = 50): string {
  const lines = content.split("\n");
  let nums: number[];
  if (!changedLines || changedLines.length === 0) {
    nums = Array.from({ length: Math.min(lines.length, max) }, (_, i) => i + 1);
  } else {
    const set = new Set<number>();
    for (const n of changedLines) for (let d = -1; d <= 1; d++) if (n + d >= 1 && n + d <= lines.length) set.add(n + d);
    nums = [...set].sort((a, b) => a - b).slice(0, max);
  }
  const out: string[] = [];
  let prev = 0;
  for (const n of nums) {
    if (prev && n > prev + 1) out.push("  …");
    out.push(`${n}: ${lines[n - 1] ?? ""}`);
    prev = n;
  }
  return out.join("\n");
}

function buildGroups(input: GuidelineEvalInput): GuidelineGroupPayload[] {
  const groups = new Map<string, { ruleSet: GuidelineRuleSet; hunks: Hunk[] }>();
  const droppedSeen = new Set<string>();
  for (const f of input.files) {
    const ruleSet = resolveGuidelinesForFile(f.filePath, input.root, input.config);
    if (!ruleSet) continue;
    if (ruleSet.dropped.length && input.log) {
      const key = ruleSet.sources.join("|");
      if (!droppedSeen.has(key)) {
        droppedSeen.add(key);
        input.log(`guidelines: nesting cap hit — using ${ruleSet.sources.join(", ")}; dropped ${ruleSet.dropped.join(", ")}`);
      }
    }
    const key = ruleSet.sources.join("|");
    if (!groups.has(key)) groups.set(key, { ruleSet, hunks: [] });
    groups.get(key)!.hunks.push({ rel: f.rel, code: buildSnippet(f.content, f.changedLines) });
  }
  return [...groups.values()].map((g) => ({ sources: g.ruleSet.sources, guidelines: g.ruleSet.text, hunks: g.hunks }));
}

function chooseBackend(config: Config): "model" | "host" {
  const e = config.guidelines?.evaluator || "auto";
  if (e === "model" || e === "host") return e;
  return isAiAvailable(config) ? "model" : "host";
}

function capTier(severity: string | undefined, cap: Tier): Tier {
  const want: Tier = severity === "error" ? "orange" : severity === "info" ? "green" : "yellow";
  return (TIER_ORDER[want] ?? 1) <= (TIER_ORDER[cap] ?? 1) ? want : cap;
}

function parseFindings(text: string): Array<Record<string, unknown>> {
  const start = text.indexOf("[");
  const end = text.lastIndexOf("]");
  if (start === -1 || end <= start) return [];
  try {
    const arr = JSON.parse(text.slice(start, end + 1));
    return Array.isArray(arr) ? arr : [];
  } catch {
    return [];
  }
}

function buildGroupPrompt(group: GuidelineGroupPayload): string {
  const hunks = group.hunks.map((h) => `--- ${h.rel} ---\n${h.code}`).join("\n\n");
  return `${group.guidelines}\n\n## Changed code\n${hunks}\n\n${instructions()}\nSchema: ${JSON.stringify(RESULT_SCHEMA)}`;
}

/**
 * Evaluate changed files against their resolved guideline sets.
 * Backend = "model" (configured provider, works headless/CI) or "host" (returns
 * materials for the calling agent to judge with its own credits — no API key).
 */
export async function evaluateGuidelines(input: GuidelineEvalInput): Promise<GuidelineEvalResult> {
  const { config } = input;
  if (config.guidelines?.enabled === false) return { mode: "model", findings: [] };
  const groups = buildGroups(input);
  if (groups.length === 0) return { mode: "model", findings: [] };

  if (chooseBackend(config) === "host") {
    const advisoryNote =
      "\n\nThis is a SELF-REVIEW (no independent model evaluated the diff). Treat any violations you find " +
      "as advisory only — surface them, do not block the change on them.";
    return {
      mode: "host",
      payload: {
        groups,
        instructions: `${SYSTEM}\n\n${instructions()}${advisoryNote}`,
        schema: RESULT_SCHEMA,
        independent: false,
        advisory: true,
      },
    };
  }

  const cap = config.guidelines?.tier ?? "yellow";
  const blocking = config.guidelines?.blocking ?? false;
  const byRel = new Map(input.files.map((f) => [f.rel, f]));
  const findings: Finding[] = [];

  for (const group of groups) {
    const { text } = await complete({
      system: SYSTEM,
      prompt: buildGroupPrompt(group),
      config,
      tier: "default",
      signal: input.signal,
      fetchImpl: input.fetchImpl,
    });
    for (const raw of parseFindings(text)) {
      const rel = String(raw.file ?? "");
      const file = byRel.get(rel);
      const line = Math.max(1, Number(raw.line) || 1);
      const codeLine = file ? (file.content.split("\n")[line - 1] ?? "").trim() : "";
      findings.push({
        ruleId: "guideline",
        tier: capTier(raw.severity as string | undefined, cap),
        blocking,
        title: String(raw.title ?? "Guideline violation"),
        message: `${String(raw.message ?? "")} (per ${group.sources.join(", ")})`,
        line,
        column: 0,
        endLine: line,
        endColumn: 0,
        code: codeLine,
        fix: null,
      });
    }
  }
  return { mode: "model", findings };
}

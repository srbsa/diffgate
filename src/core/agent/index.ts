import { resolveProvider, selectModel } from "../llm/registry.js";
import { TOOLS, executeTool } from "./tools.js";
import { openaiDriver, anthropicDriver } from "./drivers.js";
import type { Finding, Config, FetchFn, DeepReviewResult, ToolCallStep } from "../types.js";

const SYSTEM_DEEP =
  "You are a senior code reviewer performing a DEEP review of a single flagged change in a real repository. " +
  "You have read-only tools to gather evidence: search the codebase, read files, find references, and check git blame. " +
  "Make a FEW targeted tool calls — do not over-explore. Once you have enough evidence, stop calling tools and give your verdict.";

function buildPrompt({ finding, filePath, snippet, language }: { finding: Finding; filePath: string; snippet: string; language: string }): string {
  return `Flagged change to review:
- File: ${filePath}
- Tier: ${finding.tier} (${finding.title})
- Guardrail note: ${finding.message}

The changed code (${language}):
\`\`\`${language}
${snippet}
\`\`\`

Investigate the real blast radius (e.g. find call sites of changed/exported symbols, read related code). Then respond with EXACTLY:
- **Verdict:** confirmed-risk | likely-safe | needs-human
- **Why / impact:** cite the specific files or call sites you found
- **Fix:** a concrete change, or "n/a"
Keep the final answer under 180 words.`;
}

export function deepModel(config: Partial<Config>, provider: ReturnType<typeof resolveProvider>): string | null {
  const dr = config?.ai?.deepReview;
  return dr?.model || selectModel(config, "deep", provider);
}

export async function deepReview({ finding, filePath, snippet, language, cwd, config, signal, onStep, fetchImpl }: {
  finding: Finding;
  filePath: string;
  snippet: string;
  language: string;
  cwd: string;
  config: Partial<Config>;
  signal?: AbortSignal;
  onStep?: (step: ToolCallStep) => void;
  fetchImpl?: FetchFn;
}): Promise<DeepReviewResult> {
  const p = resolveProvider(config);
  const apiKey = p.apiKeyEnv ? process.env[p.apiKeyEnv] ?? null : null;
  if (!p.local && p.apiKeyEnv && !apiKey) {
    throw new Error(`No API key found in $${p.apiKeyEnv} for provider "${p.id}".`);
  }
  const model = deepModel(config, p);
  if (!model) throw new Error(`No model configured for deep review. Set ai.deepReview.model or ai.model.`);

  const maxSteps = config.ai?.deepReview?.maxSteps || 6;
  const driver = p.wire === "anthropic"
    ? anthropicDriver({ ...p, apiKey, fetchImpl })
    : openaiDriver({ ...p, apiKey, fetchImpl });

  const ctx = { cwd, config };
  const stepOpts = {
    model,
    maxTokens: config.ai?.maxTokens || 1024,
    tokenParam: config.ai?.tokenParam || "max_tokens",
    temperature: config.ai?.temperature ?? 0,
    signal,
  };

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let history = (driver as any).init(SYSTEM_DEEP, buildPrompt({ finding, filePath, snippet, language }));
  const transcript: DeepReviewResult["transcript"] = [];
  let lastText = "";

  for (let i = 0; i < maxSteps; i++) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const step = await (driver as any).step(history, TOOLS, stepOpts);
    if (step.assistantText) lastText = step.assistantText as string;
    if (!step.toolCalls || (step.toolCalls as unknown[]).length === 0) {
      return { verdict: (step.assistantText as string) || lastText, steps: i + 1, transcript, model, hitMax: false };
    }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (driver as any).appendAssistant(history, step);
    const results: Array<{ id?: string; name: string; content: string }> = [];
    for (const tc of step.toolCalls as Array<{ id?: string; name: string; input?: Record<string, unknown> }>) {
      if (onStep) onStep({ type: "tool", name: tc.name, input: tc.input || {} });
      const r = await executeTool(tc, ctx);
      results.push(r);
      transcript.push({ name: tc.name, input: tc.input || {}, output: r.content.slice(0, 300) });
    }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (driver as any).appendToolResults(history, step, results);
  }
  return { verdict: lastText || "(no verdict — reached the step limit)", steps: maxSteps, transcript, model, hitMax: true };
}

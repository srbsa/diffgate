import crypto from "crypto";
import { resolveProvider, selectModel, PROVIDERS } from "./registry.js";
import { anthropicComplete } from "./anthropic.js";
import { openaiComplete } from "./openai.js";
import type { Config, FetchFn, CompleteResult, Finding } from "../types.js";

export { PROVIDERS, resolveProvider, selectModel };

export function aiKeyEnv(config: Partial<Config>): string {
  return resolveProvider(config).apiKeyEnv || "ANTHROPIC_API_KEY";
}

export function describeProvider(config: Partial<Config>): string {
  const p = resolveProvider(config);
  return p.local ? `${p.id} (local: ${p.baseURL})` : p.id;
}

export function isAiAvailable(config: Partial<Config> | null | undefined): boolean {
  if (!config || !config.ai || !config.ai.enabled) return false;
  const p = resolveProvider(config);
  if (p.local || !p.apiKeyEnv) return true;
  return !!process.env[p.apiKeyEnv];
}

export interface CompleteCallOptions {
  system?: string;
  prompt: string;
  config: Partial<Config>;
  tier?: string;
  modelOverride?: string;
  noThink?: boolean;
  signal?: AbortSignal;
  fetchImpl?: FetchFn;
}

export async function complete({ system, prompt, config, tier = "default", modelOverride, noThink, signal, fetchImpl }: CompleteCallOptions): Promise<CompleteResult> {
  const p = resolveProvider(config);
  const apiKey = p.apiKeyEnv ? process.env[p.apiKeyEnv] ?? null : null;
  if (!p.local && p.apiKeyEnv && !apiKey) {
    throw new Error(`No API key found in $${p.apiKeyEnv} for provider "${p.id}".`);
  }
  const model = modelOverride || selectModel(config, tier, p);
  if (!model) {
    throw new Error(`No model configured for provider "${p.id}". Set "ai.model" in .diffgate.json.`);
  }
  const opts = {
    baseURL: p.baseURL,
    apiKey,
    model,
    system,
    prompt,
    maxTokens: config.ai?.maxTokens || (p.local ? 2048 : 700),
    temperature: config.ai?.temperature ?? 0,
    tokenParam: config.ai?.tokenParam || "max_tokens",
    extraHeaders: p.extraHeaders,
    // Thinking-suppression uses non-standard params (chat_template_kwargs, /no_think)
    // that strict hosted APIs reject. Realize it only for local templated runtimes
    // unless the user explicitly opts in via ai.noThink (e.g. a self-hosted gateway).
    noThink: noThink && (config.ai?.noThink ?? p.local),
    signal,
    fetchImpl,
  };
  return p.wire === "anthropic" ? anthropicComplete(opts) : openaiComplete(opts);
}

const SYSTEM = "You are a meticulous senior code reviewer. Be specific and terse. No preamble, no restating the question. If you are a reasoning model, keep your thinking process extremely brief.";

function buildPrompt({ finding, snippet, language }: { finding: Pick<Finding, "tier" | "title" | "message">; snippet: string; language: string }): string {
  return `A static code-review DiffGate flagged a ${finding.tier.toUpperCase()} issue titled "${finding.title}".
DiffGate note: ${finding.message}

Code under review (${language}):
\`\`\`${language}
${snippet}
\`\`\`

Explain concretely why this is risky in this specific code and what the reviewer should verify before approving. Keep the explanation brief (ideally 2-4 sentences). If there is an obvious safer rewrite, include it as one short code block.`;
}

const cache = new Map<string, CompleteResult>();

export async function explainFinding({ finding, snippet, language, config, signal, fetchImpl }: {
  finding: Finding;
  snippet: string;
  language: string;
  config: Partial<Config>;
  signal?: AbortSignal;
  fetchImpl?: FetchFn;
}): Promise<CompleteResult> {
  const cacheKey = crypto
    .createHash("sha1")
    .update(`${describeProvider(config)}|${finding.ruleId}|${finding.code}|${snippet}`)
    .digest("hex");
  if (cache.has(cacheKey)) return cache.get(cacheKey)!;
  const { text, model } = await complete({
    system: SYSTEM,
    prompt: buildPrompt({ finding, snippet, language }),
    config,
    tier: finding.tier,
    noThink: true,
    signal,
    fetchImpl,
  });
  const result: CompleteResult = { text, model };
  cache.set(cacheKey, result);
  return result;
}

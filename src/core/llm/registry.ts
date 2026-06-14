import type { ProviderPreset, ResolvedProvider, Config } from "../types.js";

export const PROVIDERS: Record<string, ProviderPreset> = {
  anthropic: { wire: "anthropic", baseURL: "https://api.anthropic.com", apiKeyEnv: "ANTHROPIC_API_KEY", defaultModel: "claude-sonnet-4-6", local: false },
  openai: { wire: "openai", baseURL: "https://api.openai.com/v1", apiKeyEnv: "OPENAI_API_KEY", defaultModel: "gpt-5.4-mini", local: false },
  openrouter: { wire: "openai", baseURL: "https://openrouter.ai/api/v1", apiKeyEnv: "OPENROUTER_API_KEY", defaultModel: "openai/gpt-5.4-mini", local: false, extraHeaders: { "X-Title": "DiffGate" } },
  groq: { wire: "openai", baseURL: "https://api.groq.com/openai/v1", apiKeyEnv: "GROQ_API_KEY", defaultModel: "llama-3.3-70b-versatile", local: false },
  together: { wire: "openai", baseURL: "https://api.together.xyz/v1", apiKeyEnv: "TOGETHER_API_KEY", defaultModel: "meta-llama/Llama-3.3-70B-Instruct-Turbo", local: false },
  lmstudio: { wire: "openai", baseURL: "http://localhost:1234/v1", apiKeyEnv: null, defaultModel: null, local: true },
  ollama: { wire: "openai", baseURL: "http://localhost:11434/v1", apiKeyEnv: null, defaultModel: "llama3.1", local: true },
  custom: { wire: "openai", baseURL: null, apiKeyEnv: null, defaultModel: null, local: false },
};

function isLocalURL(url: string | null | undefined): boolean {
  return !!url && /(^https?:\/\/)?(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])/.test(url);
}

function inferProvider(ai: Config["ai"] | undefined): string | null {
  if (!ai) return null;
  if (ai.baseURL) return "custom";
  const k = (ai.apiKeyEnv || "").toUpperCase();
  if (k.includes("ANTHROPIC")) return "anthropic";
  if (k.includes("OPENAI")) return "openai";
  if (k.includes("OPENROUTER")) return "openrouter";
  if (k.includes("GROQ")) return "groq";
  const m = typeof ai.model === "string" ? ai.model : "";
  if (m.startsWith("claude")) return "anthropic";
  if (m.startsWith("gpt") || m.startsWith("o1") || m.startsWith("o3") || m.startsWith("o4")) return "openai";
  return null;
}

export function resolveProvider(config: Partial<Config>): ResolvedProvider {
  const ai = (config && config.ai) || undefined;
  const id = ((ai?.provider || inferProvider(ai) || "anthropic")).toLowerCase();
  const preset = PROVIDERS[id] || PROVIDERS["anthropic"];
  const baseURL = ai?.baseURL || preset.baseURL;
  const local = ai?.local ?? (preset.local || isLocalURL(baseURL));
  return {
    id,
    wire: (ai?.wire || preset.wire) as "anthropic" | "openai",
    baseURL,
    apiKeyEnv: ai?.apiKeyEnv || preset.apiKeyEnv,
    local,
    extraHeaders: { ...(preset.extraHeaders || {}), ...(ai?.extraHeaders || {}) },
    presetModel: preset.defaultModel,
  };
}

export function selectModel(config: Partial<Config>, tier: string, provider: ResolvedProvider): string | null {
  const m = config?.ai?.model;
  if (m && typeof m === "object") {
    return (m as Record<string, string>)[tier] || (m as Record<string, string>)["default"] || provider.presetModel;
  }
  if (typeof m === "string" && m) return m;
  return provider.presetModel;
}

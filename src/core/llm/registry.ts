import type { ProviderPreset, ResolvedProvider, Config } from "../types.js";

export const PROVIDERS: Record<string, ProviderPreset> = {
  anthropic: { wire: "anthropic", baseURL: "https://api.anthropic.com", apiKeyEnv: "ANTHROPIC_API_KEY", defaultModel: "claude-sonnet-4-6", local: false },
  openai: { wire: "openai", baseURL: "https://api.openai.com/v1", apiKeyEnv: "OPENAI_API_KEY", defaultModel: "gpt-5.4-mini", local: false },
  openrouter: { wire: "openai", baseURL: "https://openrouter.ai/api/v1", apiKeyEnv: "OPENROUTER_API_KEY", defaultModel: "openai/gpt-5.4-mini", local: false, extraHeaders: { "X-Title": "DiffGate" } },
  groq: { wire: "openai", baseURL: "https://api.groq.com/openai/v1", apiKeyEnv: "GROQ_API_KEY", defaultModel: "llama-3.3-70b-versatile", local: false },
  together: { wire: "openai", baseURL: "https://api.together.xyz/v1", apiKeyEnv: "TOGETHER_API_KEY", defaultModel: "meta-llama/Llama-3.3-70B-Instruct-Turbo", local: false },
  cerebras: { wire: "openai", baseURL: "https://api.cerebras.ai/v1", apiKeyEnv: "CEREBRAS_API_KEY", defaultModel: "gpt-oss-120b", local: false },
  gemini: { wire: "openai", baseURL: "https://generativelanguage.googleapis.com/v1beta/openai", apiKeyEnv: "GEMINI_API_KEY", defaultModel: "gemini-2.5-flash", local: false },
  lmstudio: { wire: "openai", baseURL: "http://localhost:1234/v1", apiKeyEnv: null, defaultModel: null, local: true },
  ollama: { wire: "openai", baseURL: "http://localhost:11434/v1", apiKeyEnv: null, defaultModel: "llama3.1", local: true },
  custom: { wire: "openai", baseURL: null, apiKeyEnv: null, defaultModel: null, local: false },
};

function isLocalURL(url: string | null | undefined): boolean {
  return !!url && /(^https?:\/\/)?(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])/.test(url);
}

// `ai.baseURL` / `ai.apiKeyEnv` in `.diffgate.json` are repo-tracked — an untrusted repo's own
// committed config, not something the person running the tool authored. Trusting them at face
// value lets any repo redirect this tool's outbound AI calls, with whatever secret `apiKeyEnv`
// names (not just an LLM key — anything in the process env), to a host the repo also names. This
// is the same shape as CVE-2026-21852 (Claude Code project settings overriding ANTHROPIC_BASE_URL
// before the trust dialog). The fix mirrors that one: gate the two fields that control where a
// credential goes behind something a repo cannot write — an environment variable — rather than
// trusting them from config. `ai.provider` stays repo-configurable; it only *selects* a hardcoded,
// known-safe preset below, it can't invent a new endpoint.
const KNOWN_API_KEY_ENVS = new Set(
  Object.values(PROVIDERS).map((p) => p.apiKeyEnv).filter((v): v is string => !!v)
);

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

  // A repo-configured baseURL is only honored if it's a loopback address — the legitimate "point
  // everyone at my local ollama/lmstudio" pattern the built-in presets already default to — or if
  // the user set it themselves via env (which the repo cannot write). Anything else (a public,
  // repo-named host) falls back to the resolved provider's own default endpoint.
  const envBaseURL = process.env.DIFFGATE_AI_BASE_URL || null;
  const configBaseURL = ai?.baseURL && isLocalURL(ai.baseURL) ? ai.baseURL : null;
  const baseURL = envBaseURL || configBaseURL || preset.baseURL;

  // Same reasoning for apiKeyEnv: repo config may only select a *known* provider key-env-var name,
  // never an arbitrary variable name that happens to hold some other credential.
  const configApiKeyEnv = ai?.apiKeyEnv && KNOWN_API_KEY_ENVS.has(ai.apiKeyEnv) ? ai.apiKeyEnv : null;
  const apiKeyEnv = process.env.DIFFGATE_AI_API_KEY_ENV || configApiKeyEnv || preset.apiKeyEnv;

  const local = ai?.local ?? (preset.local || isLocalURL(baseURL));
  return {
    id,
    wire: (ai?.wire || preset.wire) as "anthropic" | "openai",
    baseURL,
    apiKeyEnv,
    local,
    extraHeaders: { ...(preset.extraHeaders || {}), ...(ai?.extraHeaders || {}) },
    presetModel: preset.defaultModel,
  };
}

/**
 * OpenAI's GPT-5 / o-series reasoning models changed the chat/completions contract:
 *   - `max_tokens` is rejected; you must send `max_completion_tokens`.
 *   - `temperature` only accepts the default (1); any other value 400s.
 * Detect them by model name so the wire defaults are correct with zero config,
 * across any OpenAI-compatible router (openai, openrouter, azure, custom). The
 * leading-segment strip handles namespaced ids like "openai/gpt-5.4-mini".
 */
export function isOpenAIReasoningModel(model: string | null | undefined): boolean {
  if (!model) return false;
  const m = model.toLowerCase().split("/").pop() || "";
  return /^gpt-5/.test(m) || /^o[1-9]/.test(m);
}

export function selectModel(config: Partial<Config>, tier: string, provider: ResolvedProvider): string | null {
  const m = config?.ai?.model;
  if (m && typeof m === "object") {
    return (m as Record<string, string>)[tier] || (m as Record<string, string>)["default"] || provider.presetModel;
  }
  if (typeof m === "string" && m) return m;
  return provider.presetModel;
}

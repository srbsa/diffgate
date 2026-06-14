import type { FetchFn } from "../types.js";

interface ToolDef {
  name: string;
  description: string;
  input_schema: Record<string, unknown>;
}

interface StepResult {
  assistantText: string;
  toolCalls: Array<{ id?: string; name: string; input: Record<string, unknown> }>;
  raw: unknown;
  stop?: string;
}

interface ToolResult {
  id?: string;
  content: string;
}

type OpenAIHistory = Array<Record<string, unknown>>;
interface AnthropicHistory {
  system?: string;
  messages: Array<{ role: string; content: unknown }>;
}

interface StepOpts {
  model: string;
  maxTokens?: number;
  tokenParam?: string;
  temperature?: number;
  signal?: AbortSignal;
}

interface Driver<H> {
  init(system: string, user: string): H;
  step(history: H, tools: ToolDef[], opts: StepOpts): Promise<StepResult>;
  appendAssistant(history: H, step: StepResult): void;
  appendToolResults(history: H, step: StepResult, results: ToolResult[]): void;
}

function safeJson(s: string | null | undefined): Record<string, unknown> {
  try {
    return JSON.parse(s || "{}") as Record<string, unknown>;
  } catch {
    return {};
  }
}

export function openaiDriver({ baseURL, apiKey, extraHeaders = {}, fetchImpl }: { baseURL: string | null; apiKey: string | null; extraHeaders?: Record<string, string>; fetchImpl?: FetchFn }): Driver<OpenAIHistory> {
  const url = `${(baseURL ?? "").replace(/\/$/, "")}/chat/completions`;
  const toTools = (tools: ToolDef[]) =>
    tools.map((t) => ({ type: "function", function: { name: t.name, description: t.description, parameters: t.input_schema } }));
  return {
    init(system, user) {
      const m: OpenAIHistory = [];
      if (system) m.push({ role: "system", content: system });
      m.push({ role: "user", content: user });
      return m;
    },
    async step(history, tools, { model, maxTokens = 1024, tokenParam = "max_tokens", temperature = 0, signal }) {
      const body: Record<string, unknown> = { model, messages: history, tools: toTools(tools), tool_choice: "auto" };
      body[tokenParam] = maxTokens;
      if (temperature != null) body["temperature"] = temperature;
      const headers: Record<string, string> = { "content-type": "application/json", ...extraHeaders };
      if (apiKey) headers["authorization"] = `Bearer ${apiKey}`;
      const res = await (fetchImpl || fetch)(url, { method: "POST", headers, body: JSON.stringify(body), signal });
      if (!res.ok) {
        const t = await res.text().catch(() => "");
        throw new Error(`LLM API ${res.status}: ${t.slice(0, 300)}`);
      }
      const data = await res.json() as { choices?: Array<{ message?: { content?: string; tool_calls?: Array<{ id: string; function?: { name: string; arguments?: string } }> } }> };
      const msg = (data.choices && data.choices[0] && data.choices[0].message) || {};
      const toolCalls = (msg.tool_calls || []).map((tc) => ({
        id: tc.id,
        name: (tc.function && tc.function.name) || "",
        input: safeJson(tc.function && tc.function.arguments),
      }));
      return { assistantText: (msg.content || "").trim(), toolCalls, raw: msg };
    },
    appendAssistant(history, step) {
      history.push(step.raw as Record<string, unknown>);
    },
    appendToolResults(history, _step, results) {
      for (const r of results) history.push({ role: "tool", tool_call_id: r.id, content: r.content });
    },
  };
}

export function anthropicDriver({ baseURL, apiKey, extraHeaders = {}, fetchImpl }: { baseURL: string | null; apiKey: string | null; extraHeaders?: Record<string, string>; fetchImpl?: FetchFn }): Driver<AnthropicHistory> {
  const url = `${(baseURL ?? "").replace(/\/$/, "")}/v1/messages`;
  const toTools = (tools: ToolDef[]) => tools.map((t) => ({ name: t.name, description: t.description, input_schema: t.input_schema }));
  return {
    init(system, user) {
      return { system, messages: [{ role: "user", content: user }] };
    },
    async step(history, tools, { model, maxTokens = 1024, temperature = 0, signal }) {
      const body: Record<string, unknown> = { model, max_tokens: maxTokens, system: history.system, messages: history.messages, tools: toTools(tools) };
      if (temperature != null) body["temperature"] = temperature;
      const headers: Record<string, string> = {
        "content-type": "application/json",
        "x-api-key": apiKey ?? "",
        "anthropic-version": "2023-06-01",
        ...extraHeaders,
      };
      const res = await (fetchImpl || fetch)(url, { method: "POST", headers, body: JSON.stringify(body), signal });
      if (!res.ok) {
        const t = await res.text().catch(() => "");
        throw new Error(`Anthropic API ${res.status}: ${t.slice(0, 300)}`);
      }
      const data = await res.json() as { content?: Array<{ type: string; text?: string; id?: string; name?: string; input?: Record<string, unknown> }>; stop_reason?: string };
      const content = data.content || [];
      const assistantText = content.filter((b) => b.type === "text").map((b) => b.text || "").join("\n").trim();
      const toolCalls = content.filter((b) => b.type === "tool_use").map((b) => ({ id: b.id, name: b.name || "", input: b.input || {} }));
      return { assistantText, toolCalls, raw: content, stop: data.stop_reason };
    },
    appendAssistant(history, step) {
      history.messages.push({ role: "assistant", content: step.raw });
    },
    appendToolResults(history, _step, results) {
      history.messages.push({
        role: "user",
        content: results.map((r) => ({ type: "tool_result", tool_use_id: r.id, content: r.content })),
      });
    },
  };
}

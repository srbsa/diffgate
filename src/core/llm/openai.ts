import type { CompleteOptions, CompleteResult } from "../types.js";

export async function openaiComplete({
  baseURL,
  apiKey,
  model,
  system,
  prompt,
  maxTokens = 700,
  temperature = 0,
  tokenParam = "max_tokens",
  extraHeaders = {},
  noThink = false,
  signal,
  fetchImpl,
}: CompleteOptions): Promise<CompleteResult> {
  const doFetch = fetchImpl || fetch;
  const url = `${(baseURL ?? "").replace(/\/$/, "")}/chat/completions`;

  // For reasoning models (e.g. Qwen on LM Studio) the `/no_think` soft switch
  // disables chain-of-thought; `enable_thinking` is the structured equivalent
  // honored by Qwen's chat template. Send both so whichever the server reads wins.
  const sys = noThink ? `${system ? `${system}\n` : ""}/no_think` : system;

  const messages: { role: string; content: string }[] = [];
  if (sys) messages.push({ role: "system", content: sys });
  messages.push({ role: "user", content: prompt });

  const body: Record<string, unknown> = { model, messages };
  body[tokenParam] = maxTokens;
  if (temperature != null) body["temperature"] = temperature;
  if (noThink) body["chat_template_kwargs"] = { enable_thinking: false };

  const headers: Record<string, string> = { "content-type": "application/json", ...extraHeaders };
  if (apiKey) headers["authorization"] = `Bearer ${apiKey}`;

  const res = await doFetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
    signal,
  });
  if (!res.ok) {
    const t = await res.text().catch(() => "");
    throw new Error(`LLM API ${res.status}: ${t.slice(0, 300)}`);
  }
  const data = await res.json() as { choices?: { message?: { content?: string } }[]; model?: string; usage?: unknown };
  const text = (
    data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content
      ? data.choices[0].message.content
      : ""
  ).replace(/^\s*<think>[\s\S]*?<\/think>\s*/i, "").trim();
  return { text, model: data.model || model, usage: data.usage || null };
}

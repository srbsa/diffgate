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
  signal,
  fetchImpl,
}: CompleteOptions): Promise<CompleteResult> {
  const doFetch = fetchImpl || fetch;
  const url = `${(baseURL ?? "").replace(/\/$/, "")}/chat/completions`;

  const messages: { role: string; content: string }[] = [];
  if (system) messages.push({ role: "system", content: system });
  messages.push({ role: "user", content: prompt });

  const body: Record<string, unknown> = { model, messages };
  body[tokenParam] = maxTokens;
  if (temperature != null) body["temperature"] = temperature;

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
  ).trim();
  return { text, model: data.model || model, usage: data.usage || null };
}

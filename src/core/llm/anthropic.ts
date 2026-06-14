import type { CompleteOptions, CompleteResult } from "../types.js";

const ANTHROPIC_VERSION = "2023-06-01";

export async function anthropicComplete({
  baseURL,
  apiKey,
  model,
  system,
  prompt,
  maxTokens = 700,
  temperature = 0,
  extraHeaders = {},
  signal,
  fetchImpl,
}: CompleteOptions): Promise<CompleteResult> {
  const doFetch = fetchImpl || fetch;
  const url = `${(baseURL ?? "").replace(/\/$/, "")}/v1/messages`;
  const body: Record<string, unknown> = {
    model,
    max_tokens: maxTokens,
    messages: [{ role: "user", content: prompt }],
  };
  if (system) body["system"] = system;
  if (temperature != null) body["temperature"] = temperature;

  const res = await doFetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-api-key": apiKey ?? "",
      "anthropic-version": ANTHROPIC_VERSION,
      ...extraHeaders,
    },
    body: JSON.stringify(body),
    signal,
  });
  if (!res.ok) {
    const t = await res.text().catch(() => "");
    throw new Error(`Anthropic API ${res.status}: ${t.slice(0, 300)}`);
  }
  const data = await res.json() as { content?: { type: string; text: string }[]; model?: string; usage?: unknown };
  const text = (data.content || [])
    .filter((b) => b.type === "text")
    .map((b) => b.text)
    .join("\n")
    .trim();
  return { text, model: data.model || model, usage: data.usage || null };
}

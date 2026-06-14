import test from "node:test";
import assert from "node:assert/strict";

import { resolveProvider, selectModel } from "../dist/core/llm/registry.js";
import { openaiComplete } from "../dist/core/llm/openai.js";
import { anthropicComplete } from "../dist/core/llm/anthropic.js";
import { isAiAvailable, explainFinding } from "../dist/core/llm/index.js";

function fakeFetch(captured, response) {
  return async (url, opts) => {
    captured.url = url;
    captured.opts = opts;
    captured.body = JSON.parse(opts.body);
    return { ok: true, status: 200, json: async () => response, text: async () => "" };
  };
}

test("resolveProvider defaults to anthropic", () => {
  const p = resolveProvider({ ai: {} });
  assert.equal(p.id, "anthropic");
  assert.equal(p.wire, "anthropic");
});

test("resolveProvider selects OpenAI and OpenAI-compatible presets", () => {
  assert.equal(resolveProvider({ ai: { provider: "openai" } }).wire, "openai");
  const or = resolveProvider({ ai: { provider: "openrouter" } });
  assert.equal(or.wire, "openai");
  assert.match(or.baseURL, /openrouter/);
});

test("resolveProvider infers provider from legacy apiKeyEnv (back-compat)", () => {
  const p = resolveProvider({ ai: { apiKeyEnv: "OPENAI_API_KEY" } });
  assert.equal(p.id, "openai");
});

test("custom baseURL on localhost is treated as a keyless local provider", () => {
  const p = resolveProvider({ ai: { provider: "custom", baseURL: "http://localhost:8000/v1" } });
  assert.equal(p.wire, "openai");
  assert.equal(p.local, true);
});

test("selectModel supports a single string and a per-tier map", () => {
  const prov = { presetModel: "preset-model" };
  assert.equal(selectModel({ ai: { model: "one-model" } }, "orange", prov), "one-model");
  const routed = { ai: { model: { orange: "strong", default: "cheap" } } };
  assert.equal(selectModel(routed, "orange", prov), "strong");
  assert.equal(selectModel(routed, "yellow", prov), "cheap");
  assert.equal(selectModel({ ai: {} }, "green", prov), "preset-model");
});

test("isAiAvailable: needs a key for remote, none for local", () => {
  assert.equal(isAiAvailable({ ai: { enabled: false } }), false);
  delete process.env.OPENAI_API_KEY;
  assert.equal(isAiAvailable({ ai: { enabled: true, provider: "openai" } }), false);
  process.env.OPENAI_API_KEY = "sk-test";
  assert.equal(isAiAvailable({ ai: { enabled: true, provider: "openai" } }), true);
  delete process.env.OPENAI_API_KEY;
  assert.equal(isAiAvailable({ ai: { enabled: true, provider: "lmstudio" } }), true);
});

test("openai adapter posts the right shape and parses choices", async () => {
  const cap = {};
  const out = await openaiComplete({
    baseURL: "https://api.example.com/v1",
    apiKey: "sk-x",
    model: "gpt-test",
    system: "sys",
    prompt: "hi",
    fetchImpl: fakeFetch(cap, { model: "gpt-test", choices: [{ message: { content: " hello " } }] }),
  });
  assert.match(cap.url, /\/chat\/completions$/);
  assert.equal(cap.opts.headers.authorization, "Bearer sk-x");
  assert.equal(cap.body.messages[0].role, "system");
  assert.equal(cap.body.messages[1].content, "hi");
  assert.equal(out.text, "hello");
});

test("anthropic adapter posts the right shape and parses content", async () => {
  const cap = {};
  const out = await anthropicComplete({
    baseURL: "https://api.anthropic.com",
    apiKey: "ak-x",
    model: "claude-test",
    system: "sys",
    prompt: "hi",
    fetchImpl: fakeFetch(cap, { model: "claude-test", content: [{ type: "text", text: "hi there" }] }),
  });
  assert.match(cap.url, /\/v1\/messages$/);
  assert.equal(cap.opts.headers["x-api-key"], "ak-x");
  assert.equal(cap.opts.headers["anthropic-version"], "2023-06-01");
  assert.equal(cap.body.system, "sys");
  assert.equal(out.text, "hi there");
});

test("explainFinding routes through provider + per-tier model selection", async () => {
  process.env.OPENAI_API_KEY = "sk-test";
  const cap = {};
  const config = {
    ai: { enabled: true, provider: "openai", model: { orange: "big-model", default: "small-model" } },
  };
  const finding = { tier: "orange", ruleId: "hardcoded-secret", title: "Secret", message: "msg", code: "x=secret-unique-1" };
  const res = await explainFinding({
    finding,
    snippet: "snippet-unique-1",
    language: "javascript",
    config,
    fetchImpl: fakeFetch(cap, { model: "big-model", choices: [{ message: { content: "use env vars" } }] }),
  });
  assert.equal(cap.body.model, "big-model", "orange tier should select the strong model");
  assert.equal(res.text, "use env vars");
  delete process.env.OPENAI_API_KEY;
});

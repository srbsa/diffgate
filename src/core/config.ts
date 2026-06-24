import fs from "fs";
import path from "path";
import type { Config } from "./types.js";

export const DEFAULT_CONFIG: Config = {
  deprecated: [
    { pattern: "UserService.getLegacyAvatar", replacedBy: "UserService.getUser().avatarUrl", author: "Dave (Senior Codeowner)", pr: "PR #412" },
    { pattern: "UserService.fetchUser", replacedBy: "UserService.getUser", author: "Alice (Tech Lead)", pr: "PR #389" },
    { pattern: "StripeClient.charge", replacedBy: "StripeClient.createPaymentIntent", author: "Finance Team", pr: "PR #204" },
  ],
  rules: {},
  customPatterns: [],
  ignore: ["**/node_modules/**", "**/.git/**", "**/dist/**", "**/build/**", "**/coverage/**", "**/vendor/**", "**/*.min.js"],
  gate: {
    mode: "working",
    failOn: "orange",
    agent: { mode: "advisory", autoFixFloor: "orange", maxFixesPerTurn: 3, escalateAfterTurns: 2, trustSource: "deterministic" },
  },
  ai: {
    // No explicit `provider` default: resolveProvider infers it from apiKeyEnv/model
    // (falling back to anthropic). Hardcoding it here would override a user who sets
    // only apiKeyEnv/model for another provider, forcing the wrong wire.
    enabled: false,
    model: "claude-sonnet-4-6",
    apiKeyEnv: "ANTHROPIC_API_KEY",
    baseURL: null,
    maxTokens: 700,
    temperature: 0,
    deepReview: { maxSteps: 6 },
  },
  testCommand: null,
  testScope: true,
  guidelines: { enabled: true, autoDetect: true, files: [], maxDepth: 3, maxBytesPerFile: 8000, tier: "yellow", blocking: false, evaluator: "auto" },
  graph: {
    enabled: "auto", provider: "codegraph", command: "codegraph-server", mode: "cli",
    maxCallers: 20, escalateThreshold: 1, timeoutMs: 4000,
    prContext: true, relatedTests: true, editContext: true, security: "auto", securityDeescalate: false,
  },
};

const CONFIG_NAME = ".diffgate.json";

export function findConfigPath(startDir: string): string | null {
  let dir = path.resolve(startDir);
  while (true) {
    const candidate = path.join(dir, CONFIG_NAME);
    if (fs.existsSync(candidate)) return candidate;
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

/**
 * Load environment variables from a `.env` file into process.env without adding
 * a dotenv dependency. Existing process.env values win (never clobber a real env
 * var). Walks up from startDir to find the first `.env`, mirroring findConfigPath.
 * Returns the path loaded, or null if none was found.
 */
export function loadDotenv(startDir: string): string | null {
  let dir = path.resolve(startDir);
  let envPath: string | null = null;
  while (true) {
    const candidate = path.join(dir, ".env");
    if (fs.existsSync(candidate)) { envPath = candidate; break; }
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
  let text: string;
  try { text = fs.readFileSync(envPath, "utf8"); } catch { return null; }
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq === -1) continue;
    let key = line.slice(0, eq).trim();
    if (key.startsWith("export ")) key = key.slice(7).trim();
    if (!key) continue;
    let val = line.slice(eq + 1).trim();
    const q = val[0];
    if ((q === '"' || q === "'") && val[val.length - 1] === q) {
      val = val.slice(1, -1);
      if (q === '"') val = val.replace(/\\n/g, "\n").replace(/\\"/g, '"');
    }
    if (process.env[key] === undefined) process.env[key] = val;
  }
  return envPath;
}

function normalize(raw: Partial<Config> & Record<string, unknown>): Config {
  const cfg = { ...DEFAULT_CONFIG, ...raw } as Config;
  cfg.ai = { ...DEFAULT_CONFIG.ai, ...(raw.ai || {}) };
  cfg.gate = { ...DEFAULT_CONFIG.gate, ...(raw.gate || {}) };
  cfg.gate.agent = { ...DEFAULT_CONFIG.gate.agent, ...((raw.gate || {}).agent || {}) };
  cfg.rules = { ...(raw.rules || {}) };
  cfg.deprecated = Array.isArray(raw.deprecated) ? raw.deprecated : DEFAULT_CONFIG.deprecated;
  cfg.customPatterns = Array.isArray(raw.customPatterns) ? raw.customPatterns : [];
  cfg.ignore = Array.isArray(raw.ignore) ? raw.ignore : DEFAULT_CONFIG.ignore;
  cfg.orangePatterns = raw.orangePatterns;
  cfg.testCommand = (raw.testCommand as string | null | undefined) ?? DEFAULT_CONFIG.testCommand;
  cfg.guidelines = { ...DEFAULT_CONFIG.guidelines, ...(raw.guidelines || {}) };
  cfg.graph = { ...DEFAULT_CONFIG.graph, ...(raw.graph || {}) };
  if (raw.learnings) cfg.learnings = raw.learnings as Config["learnings"];
  delete cfg.extends;
  validate(cfg);
  return cfg;
}

const TIERS = ["green", "yellow", "orange"];
const AGENT_MODES = ["advisory", "gated", "off"];
const TRUST_SOURCES = ["deterministic", "any"];
const GATE_MODES = ["staged", "working"];
const EVALUATORS = ["auto", "model", "host"];
const GRAPH_MODES = ["cli", "off"];
const GRAPH_PROVIDERS = ["codegraph"];

/** Enforce the enum-valued config fields so a typo fails loudly at load instead of silently
 *  falling back to a default behavior (e.g. agent.mode:"gated2" → silent advisory). */
function validate(cfg: Config): void {
  const oneOf = (label: string, val: unknown, allowed: string[]) => {
    if (val !== undefined && (typeof val !== "string" || !allowed.includes(val))) {
      throw new Error(`gate config: ${label} must be one of ${allowed.map((a) => `"${a}"`).join(" | ")}, got ${JSON.stringify(val)}`);
    }
  };
  const boolOrAuto = (label: string, val: unknown) => {
    if (val !== undefined && val !== true && val !== false && val !== "auto") {
      throw new Error(`gate config: ${label} must be one of true | false | "auto", got ${JSON.stringify(val)}`);
    }
  };
  oneOf("gate.mode", cfg.gate.mode, GATE_MODES);
  oneOf("failOn", cfg.gate.failOn, TIERS);
  const agent = cfg.gate.agent;
  if (agent) {
    oneOf("agent.mode", agent.mode, AGENT_MODES);
    oneOf("agent.autoFixFloor", agent.autoFixFloor, TIERS);
    oneOf("agent.trustSource", agent.trustSource, TRUST_SOURCES);
  }
  const guidelines = cfg.guidelines;
  if (guidelines) {
    oneOf("guidelines.evaluator", guidelines.evaluator, EVALUATORS);
    oneOf("guidelines.tier", guidelines.tier, TIERS);
  }
  const graph = cfg.graph;
  if (graph) {
    oneOf("graph.mode", graph.mode, GRAPH_MODES);
    oneOf("graph.provider", graph.provider, GRAPH_PROVIDERS);
    boolOrAuto("graph.enabled", graph.enabled);
    boolOrAuto("graph.security", graph.security);
  }
  if (cfg.testScope !== undefined && typeof cfg.testScope !== "boolean") {
    throw new Error(`config: testScope must be true or false, got ${JSON.stringify(cfg.testScope)}`);
  }
}

type RawConfig = Partial<Config> & Record<string, unknown>;

/** Resolve a single `extends` entry to a config file path. */
function resolveExtendsPath(entry: string, baseDir: string): string | null {
  // Explicit relative/absolute path.
  if (entry.startsWith(".") || path.isAbsolute(entry)) {
    let p = path.resolve(baseDir, entry);
    if (fs.existsSync(p) && fs.statSync(p).isDirectory()) p = path.join(p, CONFIG_NAME);
    return fs.existsSync(p) ? p : null;
  }
  // Bare name → resolve as a package providing a policy pack.
  for (const cand of [
    path.join(baseDir, "node_modules", entry, CONFIG_NAME),
    path.join(baseDir, "node_modules", entry, "diffgate.json"),
    path.join(baseDir, entry),
  ]) {
    if (fs.existsSync(cand)) return cand;
  }
  return null;
}

/** base-first deep merge: arrays concat (ignore deduped), plain objects shallow-merge, scalars override. */
function mergeRaw(base: RawConfig, over: RawConfig): RawConfig {
  const out: RawConfig = { ...base };
  for (const [k, v] of Object.entries(over)) {
    if (k === "extends") continue;
    const prev = out[k];
    if (Array.isArray(v) && Array.isArray(prev)) {
      out[k] = k === "ignore" ? [...new Set([...prev, ...v])] : [...prev, ...v];
    } else if (isPlainObject(v) && isPlainObject(prev)) {
      out[k] = { ...(prev as object), ...(v as object) };
    } else {
      out[k] = v;
    }
  }
  return out;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

/** Read a config file and recursively fold in everything it `extends` (base-first). */
function loadRawWithExtends(filePath: string, seen: Set<string>): RawConfig {
  const real = fs.realpathSync(filePath);
  if (seen.has(real)) throw new Error(`Circular extends detected at ${filePath}`);
  if (seen.size > 10) throw new Error(`extends chain too deep (>10) at ${filePath}`);
  seen.add(real);

  const self = JSON.parse(fs.readFileSync(filePath, "utf-8")) as RawConfig;
  const ext = self.extends;
  if (!ext) return self;

  const entries = Array.isArray(ext) ? ext : [ext];
  const baseDir = path.dirname(filePath);
  let merged: RawConfig = {};
  for (const entry of entries) {
    const resolved = resolveExtendsPath(String(entry), baseDir);
    if (!resolved) throw new Error(`extends target not found: "${entry}" (from ${filePath})`);
    merged = mergeRaw(merged, loadRawWithExtends(resolved, new Set(seen)));
  }
  return mergeRaw(merged, self);
}

export function loadConfig(startDir: string): { config: Config; path: string | null } {
  const found = findConfigPath(startDir);
  if (!found) return { config: normalize({}), path: null };
  try {
    const raw = loadRawWithExtends(found, new Set());
    return { config: normalize(raw), path: found };
  } catch (e) {
    const err = new Error(`Failed to parse ${found}: ${(e as Error).message}`);
    (err as Error & { configPath?: string }).configPath = found;
    throw err;
  }
}

function globToRegExp(glob: string): RegExp {
  let re = glob.replace(/[.+^${}()|\\]/g, "\\$&");
  re = re.replace(/\*\*\//g, " SLASH ");
  re = re.replace(/\*\*/g, " DSTAR ");
  re = re.replace(/\*/g, "[^/]*");
  re = re.replace(/\?/g, ".");
  re = re.replace(/ SLASH /g, "(?:.*/)?");
  re = re.replace(/ DSTAR /g, ".*");
  return new RegExp("^" + re + "$");
}

export function isIgnored(filePath: string, config: Config, cwd: string): boolean {
  let rel = path.relative(cwd, filePath).split(path.sep).join("/");
  if (rel.startsWith("../") || rel === "") rel = path.basename(filePath);
  const base = path.basename(filePath);
  for (const glob of config.ignore || []) {
    const re = globToRegExp(glob);
    if (re.test(rel)) return true;
    if (!glob.includes("/") && re.test(base)) return true;
  }
  return false;
}

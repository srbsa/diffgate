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
  gate: { mode: "working", failOn: "orange" },
  ai: {
    enabled: false,
    provider: "anthropic",
    model: "claude-sonnet-4-6",
    apiKeyEnv: "ANTHROPIC_API_KEY",
    baseURL: null,
    maxTokens: 700,
    temperature: 0,
    deepReview: { maxSteps: 6 },
  },
  testCommand: null,
};

const CONFIG_NAME = ".guardrails.json";

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

function normalize(raw: Partial<Config> & Record<string, unknown>): Config {
  const cfg = { ...DEFAULT_CONFIG, ...raw } as Config;
  cfg.ai = { ...DEFAULT_CONFIG.ai, ...(raw.ai || {}) };
  cfg.gate = { ...DEFAULT_CONFIG.gate, ...(raw.gate || {}) };
  cfg.rules = { ...(raw.rules || {}) };
  cfg.deprecated = Array.isArray(raw.deprecated) ? raw.deprecated : DEFAULT_CONFIG.deprecated;
  cfg.customPatterns = Array.isArray(raw.customPatterns) ? raw.customPatterns : [];
  cfg.ignore = Array.isArray(raw.ignore) ? raw.ignore : DEFAULT_CONFIG.ignore;
  cfg.orangePatterns = raw.orangePatterns;
  cfg.testCommand = (raw.testCommand as string | null | undefined) ?? DEFAULT_CONFIG.testCommand;
  return cfg;
}

export function loadConfig(startDir: string): { config: Config; path: string | null } {
  const found = findConfigPath(startDir);
  if (!found) return { config: normalize({}), path: null };
  try {
    const raw = JSON.parse(fs.readFileSync(found, "utf-8")) as Partial<Config> & Record<string, unknown>;
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

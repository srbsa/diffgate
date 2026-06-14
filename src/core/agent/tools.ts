import fs from "fs";
import path from "path";
import { execFileSync } from "child_process";
import { blameLine } from "../git.js";

const MAX_GREP = 40;
const MAX_READ_LINES = 200;
const MAX_OUTPUT = 4000;

interface ToolCtx {
  cwd: string;
  config?: unknown;
}

interface ToolDef {
  name: string;
  description: string;
  input_schema: {
    type: string;
    properties: Record<string, unknown>;
    required?: string[];
  };
  run: (input: Record<string, unknown>, ctx: ToolCtx) => unknown;
}

function safeResolve(cwd: string, p: string): string {
  const root = path.resolve(cwd);
  const abs = path.resolve(root, p || ".");
  if (abs !== root && !abs.startsWith(root + path.sep)) {
    throw new Error(`path "${p}" escapes the repository root`);
  }
  return abs;
}

function clip(s: string): string {
  return s.length > MAX_OUTPUT ? s.slice(0, MAX_OUTPUT) + "\n…(truncated)" : s;
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function jsGrep(cwd: string, pattern: string, maxResults: number): string {
  let re: RegExp;
  try {
    re = new RegExp(pattern);
  } catch {
    re = new RegExp(escapeRe(pattern));
  }
  const out: string[] = [];
  const skip = new Set(["node_modules", ".git", "dist", "build", "coverage"]);
  const walk = (dir: string): void => {
    if (out.length >= maxResults) return;
    let entries: fs.Dirent[] = [];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (out.length >= maxResults) return;
      if (e.name.startsWith(".") && e.name !== ".env") continue;
      const fp = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (!skip.has(e.name)) walk(fp);
      } else if (e.isFile()) {
        let content: string;
        try {
          if (fs.statSync(fp).size > 512 * 1024) continue;
          content = fs.readFileSync(fp, "utf-8");
        } catch {
          continue;
        }
        if (content.indexOf("\x00") !== -1) continue;
        const lines = content.split("\n");
        for (let i = 0; i < lines.length && out.length < maxResults; i++) {
          if (re.test(lines[i])) {
            out.push(`${path.relative(cwd, fp)}:${i + 1}:${lines[i].slice(0, 200)}`);
          }
        }
      }
    }
  };
  walk(cwd);
  return out.join("\n");
}

function runGrep({ pattern, glob, maxResults = MAX_GREP }: Record<string, unknown>, ctx: ToolCtx): string {
  const cap = Math.min((maxResults as number) || MAX_GREP, MAX_GREP);
  let out: string | null = null;
  try {
    const args = ["grep", "-n", "-I", "-E", "--no-color", "-e", pattern as string];
    if (glob) args.push("--", `*${glob}`);
    out = execFileSync("git", args, { cwd: ctx.cwd, encoding: "utf-8", stdio: ["ignore", "pipe", "ignore"] });
  } catch (e) {
    if ((e as NodeJS.ErrnoException & { status?: number }).status === 1) out = "";
    else out = null;
  }
  if (out === null) out = jsGrep(ctx.cwd, pattern as string, cap);
  const all = out.split("\n").filter(Boolean);
  const matches = all.slice(0, cap).map((l) => {
    const m = l.match(/^(.*?):(\d+):(.*)$/);
    return m ? { file: m[1], line: Number(m[2]), text: m[3].slice(0, 200) } : { text: l };
  });
  return JSON.stringify({ matches, truncated: all.length > cap });
}

export const TOOLS: ToolDef[] = [
  {
    name: "grep",
    description: "Search the repository with an extended-regex pattern. Returns matching file:line:text.",
    input_schema: {
      type: "object",
      properties: {
        pattern: { type: "string", description: "Extended regex to search for." },
        glob: { type: "string", description: "Optional filename filter, e.g. '.ts'." },
      },
      required: ["pattern"],
    },
    run: runGrep,
  },
  {
    name: "find_references",
    description: "Find references to a symbol name across the repository (whole-word search).",
    input_schema: {
      type: "object",
      properties: { symbol: { type: "string", description: "Identifier to look for." } },
      required: ["symbol"],
    },
    run: ({ symbol }: Record<string, unknown>, ctx: ToolCtx) => runGrep({ pattern: `\\b${escapeRe(symbol as string)}\\b` }, ctx),
  },
  {
    name: "read_file",
    description: "Read a file (optionally a line range, max 200 lines) from the repository.",
    input_schema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Repo-relative path." },
        startLine: { type: "integer" },
        endLine: { type: "integer" },
      },
      required: ["path"],
    },
    run: ({ path: p, startLine, endLine }: Record<string, unknown>, ctx: ToolCtx): string => {
      const abs = safeResolve(ctx.cwd, p as string);
      const lines = fs.readFileSync(abs, "utf-8").split("\n");
      const s = Math.max(1, (startLine as number) || 1);
      const e = Math.min(lines.length, (endLine as number) || Math.min(lines.length, s + MAX_READ_LINES - 1));
      const body = lines.slice(s - 1, e).map((t, i) => `${s + i}: ${t}`).join("\n");
      return clip(`// ${p} (lines ${s}-${e} of ${lines.length})\n${body}`);
    },
  },
  {
    name: "git_blame",
    description: "Who last changed a specific line (author, commit, summary).",
    input_schema: {
      type: "object",
      properties: { path: { type: "string" }, line: { type: "integer" } },
      required: ["path", "line"],
    },
    run: ({ path: p, line }: Record<string, unknown>, ctx: ToolCtx): string => {
      safeResolve(ctx.cwd, p as string);
      const b = blameLine(ctx.cwd, p as string, line as number);
      return JSON.stringify(b || { error: "no blame available" });
    },
  },
];

const BY_NAME = new Map(TOOLS.map((t) => [t.name, t]));

export async function executeTool(call: { id?: string; name: string; input?: Record<string, unknown> }, ctx: ToolCtx): Promise<{ id?: string; name: string; content: string }> {
  const tool = BY_NAME.get(call.name);
  let content: string;
  if (!tool) {
    content = `ERROR: unknown tool "${call.name}"`;
  } else {
    try {
      const result = await tool.run(call.input || {}, ctx);
      content = typeof result === "string" ? result : JSON.stringify(result);
    } catch (e) {
      content = `ERROR: ${(e as Error).message}`;
    }
  }
  return { id: call.id, name: call.name, content: clip(String(content)) };
}

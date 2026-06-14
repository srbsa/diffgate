import { exec } from "child_process";
import { TIER_ORDER } from "./tiers.js";
import type { Finding, Config } from "./types.js";

export interface CommandResult {
  command: string;
  success: boolean;
  code: number;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  durationMs: number;
}

export function runCommand(command: string, cwd: string, timeoutMs = 10 * 60 * 1000): Promise<CommandResult> {
  const startedAt = Date.now();
  return new Promise((resolve) => {
    exec(command, { cwd, timeout: timeoutMs, maxBuffer: 32 * 1024 * 1024 }, (error, stdout, stderr) => {
      resolve({
        command,
        success: !error,
        code: error ? ((error as NodeJS.ErrnoException).code ? Number((error as NodeJS.ErrnoException).code) : 1) : 0,
        stdout: stdout || "",
        stderr: stderr || "",
        timedOut: !!(error && (error as NodeJS.ErrnoException & { killed?: boolean }).killed),
        durationMs: Date.now() - startedAt,
      });
    });
  });
}

export function shouldGate(findings: Finding[], config: Config): boolean {
  const threshold = TIER_ORDER[config?.gate?.failOn || "orange"] ?? 2;
  return findings.some((f) => f.blocking || (TIER_ORDER[f.tier] ?? 0) >= threshold);
}

export async function runGate({ cwd, config, findings }: { cwd: string; config: Config; findings: Finding[] }): Promise<{ ran: boolean; reason?: string } & Partial<CommandResult>> {
  if (!config.testCommand) return { ran: false, reason: "no-test-command" };
  if (!shouldGate(findings, config)) return { ran: false, reason: "below-threshold" };
  const result = await runCommand(config.testCommand, cwd);
  return { ran: true, ...result };
}

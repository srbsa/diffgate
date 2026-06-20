// Smarter onboarding: inspect the repo and produce a tailored .diffgate.json so the
// first run is useful with zero hand-editing (the PLG "first PR reviewed in <5 min" path).
import fs from "fs";
import path from "path";

export interface DetectedDefaults {
  testCommand: string | null;
  languages: string[];
  guidelineFiles: string[];
  reasons: string[];
}

const GUIDELINE_FILES = ["AGENTS.md", "CLAUDE.md", "GEMINI.md", ".cursorrules", ".windsurfrules"];

const EXT_LANG: Record<string, string> = {
  ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
  ".ts": "typescript", ".tsx": "typescript",
  ".py": "python", ".go": "go", ".java": "java", ".rb": "ruby", ".rs": "rust", ".php": "php",
};

function exists(cwd: string, name: string): boolean {
  try {
    return fs.existsSync(path.join(cwd, name));
  } catch {
    return false;
  }
}

function readJson(cwd: string, name: string): Record<string, unknown> | null {
  try {
    return JSON.parse(fs.readFileSync(path.join(cwd, name), "utf-8"));
  } catch {
    return null;
  }
}

function detectTestCommand(cwd: string, reasons: string[]): string | null {
  const pkg = readJson(cwd, "package.json") as { scripts?: Record<string, string> } | null;
  const testScript = pkg?.scripts?.["test"];
  if (testScript && !/no test specified/i.test(testScript)) {
    reasons.push("found a `test` script in package.json → `npm test`");
    return "npm test";
  }
  if (exists(cwd, "pyproject.toml") || exists(cwd, "pytest.ini") || exists(cwd, "tox.ini")) {
    reasons.push("found a Python project config → `pytest`");
    return "pytest";
  }
  if (exists(cwd, "go.mod")) {
    reasons.push("found go.mod → `go test ./...`");
    return "go test ./...";
  }
  if (exists(cwd, "Cargo.toml")) {
    reasons.push("found Cargo.toml → `cargo test`");
    return "cargo test";
  }
  if (exists(cwd, "Makefile")) {
    try {
      const mk = fs.readFileSync(path.join(cwd, "Makefile"), "utf-8");
      if (/^test\s*:/m.test(mk)) {
        reasons.push("found a `test` target in Makefile → `make test`");
        return "make test";
      }
    } catch {
      /* ignore */
    }
  }
  reasons.push("no test runner detected — set testCommand manually to enable the gate");
  return null;
}

function detectLanguages(cwd: string, reasons: string[]): string[] {
  const seen = new Set<string>();
  const scanDirs = [cwd, path.join(cwd, "src"), path.join(cwd, "lib"), path.join(cwd, "app")];
  for (const dir of scanDirs) {
    let entries: fs.Dirent[] = [];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      if (!e.isFile()) continue;
      const lang = EXT_LANG[path.extname(e.name).toLowerCase()];
      if (lang) seen.add(lang);
    }
  }
  const langs = [...seen].sort();
  if (langs.length) reasons.push(`detected languages: ${langs.join(", ")}`);
  return langs;
}

export function detectProjectDefaults(cwd: string): DetectedDefaults {
  const reasons: string[] = [];
  const testCommand = detectTestCommand(cwd, reasons);
  const languages = detectLanguages(cwd, reasons);
  const guidelineFiles = GUIDELINE_FILES.filter((f) => exists(cwd, f));
  if (guidelineFiles.length) reasons.push(`will enforce guidelines from: ${guidelineFiles.join(", ")}`);
  return { testCommand, languages, guidelineFiles, reasons };
}

/** Merge detected defaults into a base config template. */
export function tailorConfig(base: Record<string, unknown>, detected: DetectedDefaults): Record<string, unknown> {
  return {
    ...base,
    testCommand: detected.testCommand,
    guidelines: {
      ...(base["guidelines"] as object),
      enabled: detected.guidelineFiles.length > 0 || (base["guidelines"] as { enabled?: boolean })?.enabled !== false,
    },
  };
}

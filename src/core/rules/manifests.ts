/**
 * Line classification for dependency manifests: which lines of a manifest actually declare
 * dependencies, so the `dependency-manifest` rule can stay quiet on version-only bumps,
 * scripts edits, and other metadata churn (release commits were tripping it on every bump).
 *
 * Returns a 0-indexed boolean array parallel to `lines` (true = dependency-relevant), or
 * `null` when the format isn't recognized — callers should treat null as "everything counts".
 */

const PACKAGE_JSON_DEP_KEYS = new Set([
  "dependencies", "devdependencies", "peerdependencies", "optionaldependencies",
  "bundleddependencies", "bundledependencies", "overrides", "resolutions", "pnpm",
]);
const COMPOSER_DEP_KEYS = new Set(["require", "require-dev", "replace", "conflict", "provide"]);

/** JSON manifests: mark lines inside top-level dependency sections. String-aware brace scan
 *  so `"scripts": { "build": "echo {}" }` doesn't corrupt depth tracking. */
function jsonDepLines(lines: string[], depKeys: Set<string>): boolean[] {
  const relevant = new Array<boolean>(lines.length).fill(false);
  let depth = 0;
  let section: string | null = null;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (depth === 1) {
      const key = /^\s*"([^"]+)"\s*:/.exec(line);
      if (key) section = key[1].toLowerCase();
    }
    relevant[i] = section !== null && depKeys.has(section);
    let inStr = false;
    for (let j = 0; j < line.length; j++) {
      const c = line[j];
      if (inStr) {
        if (c === "\\") j++;
        else if (c === '"') inStr = false;
      } else if (c === '"') inStr = true;
      else if (c === "{" || c === "[") depth++;
      else if (c === "}" || c === "]") depth--;
    }
    // Keep the section alive across a bare `"key":` line whose opening brace sits on the
    // next line (Allman-style formatters); otherwise clear once its object closes.
    if (depth <= 1 && !/:\s*$/.test(line)) section = null;
  }
  return relevant;
}

/** TOML manifests (Cargo.toml, pyproject.toml): dependency-named `[section]`s, plus the
 *  `dependencies = [...]` arrays PEP 621 puts inside `[project]`. */
function tomlDepLines(lines: string[]): boolean[] {
  const relevant = new Array<boolean>(lines.length).fill(false);
  let section = "";
  let sectionIsDep = false;
  let arrayDepth = 0;
  const bracketDelta = (s: string): number => {
    let d = 0, inStr: string | null = null;
    for (const c of s) {
      if (inStr) { if (c === inStr) inStr = null; continue; }
      if (c === '"' || c === "'") inStr = c;
      else if (c === "[") d++;
      else if (c === "]") d--;
    }
    return d;
  };
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (arrayDepth > 0) {
      relevant[i] = true;
      arrayDepth = Math.max(0, arrayDepth + bracketDelta(line));
      continue;
    }
    const header = /^\s*\[+([^\]]+)\]/.exec(line);
    if (header) {
      section = header[1].toLowerCase();
      sectionIsDep = /dependenc/.test(section);
      relevant[i] = sectionIsDep;
      continue;
    }
    // `[build-system] requires = [...]` declares build-time packages (PEP 518).
    if (section === "build-system" && /^\s*requires\s*=/.test(line)) {
      relevant[i] = true;
      arrayDepth = Math.max(0, bracketDelta(line));
      continue;
    }
    if (/^\s*(optional-dependencies|dev-dependencies|dependencies)\s*=/.test(line)) {
      relevant[i] = true;
      arrayDepth = Math.max(0, bracketDelta(line));
      continue;
    }
    relevant[i] = sectionIsDep;
  }
  return relevant;
}

/** go.mod: require/replace/exclude/tool directives, inline or block form. */
function goModDepLines(lines: string[]): boolean[] {
  const relevant = new Array<boolean>(lines.length).fill(false);
  let inBlock = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (inBlock) {
      relevant[i] = true;
      if (/^\s*\)/.test(line)) inBlock = false;
      continue;
    }
    if (/^\s*(require|replace|exclude|tool)\b/.test(line)) {
      relevant[i] = true;
      if (/\(\s*$/.test(line)) inBlock = true;
    }
  }
  return relevant;
}

/** pom.xml: <dependencies> and <dependencyManagement> subtrees. The project's own <version>
 *  stays quiet, and so does <parent> — multi-module reactor releases bump the parent version
 *  in every child pom, which is exactly the release noise this classifier exists to kill.
 *  (Accepted miss: upgrading an external parent like spring-boot-starter-parent.) */
function pomDepLines(lines: string[]): boolean[] {
  const relevant = new Array<boolean>(lines.length).fill(false);
  let depth = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const opens = (line.match(/<(dependencies|dependencyManagement)\b[^/>]*>/g) || []).length;
    const closes = (line.match(/<\/(dependencies|dependencyManagement)>/g) || []).length;
    relevant[i] = depth > 0 || opens > 0;
    depth = Math.max(0, depth + opens - closes);
  }
  return relevant;
}

const GRADLE_DEP_CONFIG =
  /^\s*(implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly|testCompileOnly|annotationProcessor|classpath|kapt|ksp)\s*[('"]/;

/** build.gradle: the dependencies { } block plus bare configuration lines (buildscript classpath). */
function gradleDepLines(lines: string[]): boolean[] {
  const relevant = new Array<boolean>(lines.length).fill(false);
  let blockDepth = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (blockDepth > 0) {
      relevant[i] = true;
      blockDepth += (line.match(/\{/g) || []).length - (line.match(/\}/g) || []).length;
      if (blockDepth < 0) blockDepth = 0;
      continue;
    }
    if (/^\s*dependencies\s*\{/.test(line)) {
      relevant[i] = true;
      blockDepth = 1 + (line.match(/\{/g) || []).length - 1 - (line.match(/\}/g) || []).length;
      if (blockDepth < 0) blockDepth = 0;
      continue;
    }
    relevant[i] = GRADLE_DEP_CONFIG.test(line);
  }
  return relevant;
}

/** Flat formats where nearly every line is a dependency: skip only blanks and comments. */
function flatDepLines(lines: string[], comment: RegExp): boolean[] {
  return lines.map((l) => l.trim().length > 0 && !comment.test(l));
}

export function dependencyRelevantLines(baseName: string, lines: string[]): boolean[] | null {
  switch (baseName) {
    case "package.json": return jsonDepLines(lines, PACKAGE_JSON_DEP_KEYS);
    case "composer.json": return jsonDepLines(lines, COMPOSER_DEP_KEYS);
    case "cargo.toml":
    case "pyproject.toml": return tomlDepLines(lines);
    case "go.mod": return goModDepLines(lines);
    case "pom.xml": return pomDepLines(lines);
    case "build.gradle":
    case "build.gradle.kts": return gradleDepLines(lines);
    case "requirements.txt": return flatDepLines(lines, /^\s*#/);
    case "gemfile": return flatDepLines(lines, /^\s*#/);
    default: return null;
  }
}

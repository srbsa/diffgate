// Comment masking for pattern rules.
//
// JS/TS get AST precision (comments/strings are never matched). Every other language uses regex
// pattern rules that match raw text — so commented-out code (`// eval(x)`, `# os.system(...)`,
// `-- DROP TABLE users`) trips security rules and generates noise. This module blanks comment
// regions to spaces (preserving line/column so finding positions stay exact) before pattern
// matching.
//
// Safety posture:
//   - Only COMMENTS are masked. Strings are left intact, because secrets and SQL live in string
//     literals (`db.query("DROP …")`, `key = "AKIA…"`) — masking them would hide real findings.
//   - Rules where a comment hit is still real (`hardcoded-secret`, `todo-marker`) set `scanRaw` and
//     bypass masking entirely (see types.ts). So a secret committed inside a comment is still caught.
//   - Strings are tracked only to locate comment boundaries correctly (so `"http://x"` is not read
//     as a `//` comment) — their contents are never blanked.

interface Syntax {
  line: string[];
  block: [string, string][];
  /** string delimiters; `multiline` ones (python triple, go/js backtick) carry across lines. */
  strings: { open: string; close: string; multiline?: boolean; escape?: boolean }[];
}

const DQ = { open: '"', close: '"', escape: true };
const SQ = { open: "'", close: "'", escape: true };

const C_FAMILY: Syntax = { line: ["//"], block: [["/*", "*/"]], strings: [DQ, SQ] };
const C_FAMILY_BACKTICK: Syntax = { line: ["//"], block: [["/*", "*/"]], strings: [{ open: "`", close: "`", multiline: true }, DQ, SQ] };
const HASH: Syntax = { line: ["#"], block: [], strings: [DQ, SQ] };
const PYTHON: Syntax = {
  line: ["#"], block: [],
  strings: [
    { open: '"""', close: '"""', multiline: true }, { open: "'''", close: "'''", multiline: true }, DQ, SQ,
  ],
};
const RUBY: Syntax = { line: ["#"], block: [["=begin", "=end"]], strings: [DQ, SQ] };
const SQL: Syntax = { line: ["--"], block: [["/*", "*/"]], strings: [SQ] };
const GO: Syntax = { line: ["//"], block: [["/*", "*/"]], strings: [{ open: "`", close: "`", multiline: true }, DQ] };
const HTML: Syntax = { line: [], block: [["<!--", "-->"]], strings: [DQ, SQ] };

const BY_LANGUAGE: Record<string, Syntax> = {
  javascript: C_FAMILY_BACKTICK, typescript: C_FAMILY_BACKTICK,
  java: C_FAMILY, c: C_FAMILY, cpp: C_FAMILY, csharp: C_FAMILY, rust: C_FAMILY,
  swift: C_FAMILY, kotlin: C_FAMILY, scala: C_FAMILY, php: C_FAMILY, dart: C_FAMILY,
  go: GO,
  python: PYTHON,
  ruby: RUBY,
  shell: HASH, bash: HASH, yaml: HASH, toml: HASH, dockerfile: HASH, perl: HASH, r: HASH,
  sql: SQL,
  html: HTML, xml: HTML, vue: HTML, markdown: HTML,
};

function syntaxFor(language: string): Syntax | null {
  return BY_LANGUAGE[language] || null;
}

interface Carry {
  kind: "block" | "string";
  close: string;
}

/** Returns `lines` with comment regions replaced by spaces. No-op for unknown languages. */
export function maskComments(lines: string[], language: string): string[] {
  const syn = syntaxFor(language);
  if (!syn) return lines;

  const out: string[] = [];
  let carry: Carry | null = null;

  for (const line of lines) {
    const chars = line.split("");
    let i = 0;

    if (carry) {
      const idx = line.indexOf(carry.close);
      if (idx === -1) {
        if (carry.kind === "block") blank(chars, 0, line.length);
        out.push(chars.join(""));
        continue;
      }
      const end = idx + carry.close.length;
      if (carry.kind === "block") blank(chars, 0, end);
      i = end;
      carry = null;
    }

    while (i < line.length) {
      // 1) string starts — never masked; only tracked to find comment boundaries.
      const str = startsWithAny(line, i, syn.strings.map((s) => s.open));
      if (str !== null) {
        const def = syn.strings[str];
        const after = i + def.open.length;
        const closeIdx = findClose(line, after, def.close, def.escape === true);
        if (closeIdx === -1) {
          if (def.multiline) { carry = { kind: "string", close: def.close }; i = line.length; }
          else i = line.length; // unterminated single-line string — stop scanning (lenient)
        } else {
          i = closeIdx + def.close.length;
        }
        continue;
      }
      // 2) block comment starts
      const blk = syn.block.find((b) => line.startsWith(b[0], i));
      if (blk) {
        const after = i + blk[0].length;
        const closeIdx = line.indexOf(blk[1], after);
        if (closeIdx === -1) { blank(chars, i, line.length); carry = { kind: "block", close: blk[1] }; break; }
        blank(chars, i, closeIdx + blk[1].length);
        i = closeIdx + blk[1].length;
        continue;
      }
      // 3) line comment starts → blank to end of line
      if (syn.line.some((t) => line.startsWith(t, i))) {
        blank(chars, i, line.length);
        break;
      }
      i++;
    }

    out.push(chars.join(""));
  }

  return out;
}

function blank(chars: string[], start: number, end: number): void {
  for (let k = start; k < end && k < chars.length; k++) {
    if (chars[k] !== "\t") chars[k] = " ";
  }
}

function startsWithAny(line: string, i: number, tokens: string[]): number | null {
  for (let t = 0; t < tokens.length; t++) if (line.startsWith(tokens[t], i)) return t;
  return null;
}

/** Index of the closing delimiter at/after `from`, honoring backslash escapes when `escape`. */
function findClose(line: string, from: number, close: string, escape: boolean): number {
  let i = from;
  while (i < line.length) {
    if (escape && line[i] === "\\") { i += 2; continue; }
    if (line.startsWith(close, i)) return i;
    i++;
  }
  return -1;
}

// Native, code-graph-free reasoning for injection findings.
//
// CodeGraph (when present) adds *cross-file* taint tracing. This module gives EVERY user a useful
// intra-file slice for free: it answers "is the flagged value produced by a recognized sanitizer?"
// so we can DOWN-tier an XSS finding from blocking to review — turning "looks like a sink" into
// "sink, but sanitized in place: verify". It also adds entropy/placeholder precision to the secret
// rule so obvious non-secrets stop generating noise.
//
// Safety posture: we ONLY ever down-tier (orange → yellow, non-blocking); we never suppress a
// security finding outright. A missed sanitizer therefore cannot hide a real vulnerability — it
// just keeps the finding blocking, which is the safe default.

import { memberName } from "./parsers/javascript.js";
import type { AstNode, RuleContext } from "./types.js";

// --- intra-file AST walking -------------------------------------------------

const SKIP_KEYS = new Set([
  "loc", "start", "end", "range", "extra",
  "leadingComments", "trailingComments", "innerComments", "comments", "tokens",
]);

function eachChild(node: AstNode, fn: (child: AstNode) => void): void {
  for (const key of Object.keys(node)) {
    if (SKIP_KEYS.has(key)) continue;
    const value = (node as Record<string, unknown>)[key];
    if (Array.isArray(value)) {
      for (const c of value) if (c && typeof (c as AstNode).type === "string") fn(c as AstNode);
    } else if (value && typeof (value as AstNode).type === "string") {
      fn(value as AstNode);
    }
  }
}

/** The init/right-hand side a local identifier was last bound to, anywhere in the file. */
function declInit(idName: string, root: AstNode): AstNode | null {
  let found: AstNode | null = null;
  const visit = (n: AstNode) => {
    const node = n as Record<string, any>;
    if (node.type === "VariableDeclarator" && node.id?.type === "Identifier" && node.id.name === idName) {
      found = node.init as AstNode;
    } else if (node.type === "AssignmentExpression" && node.left?.type === "Identifier" && node.left.name === idName) {
      found = node.right as AstNode;
    }
    eachChild(n, visit);
  };
  visit(root);
  return found;
}

// --- recognized sanitizers, per injection rule -----------------------------

const SANITIZER: Record<string, RegExp> = {
  // DOMPurify.sanitize, sanitizeHtml, escapeHtml, he.encode, encodeURIComponent, validator.escape …
  "xss-sink": /(?:^|\.)(?:sanitize|sanitizeHtml|escapeHtml|encodeURIComponent|encodeURI|escape|encode)$/i,
};

function calleeNameOf(node: AstNode | null | undefined): string | null {
  if (!node || node.type !== "CallExpression") return null;
  const callee = (node as Record<string, any>).callee as AstNode | undefined;
  return (callee ? memberName(callee) : null) || ((callee as Record<string, any>)?.name ?? null);
}

/** If `node` is a sanitizer call recognized for `ruleId`, return its callee name; else null. */
export function isSanitizerCall(node: AstNode | null | undefined, ruleId: string): string | null {
  const name = calleeNameOf(node);
  const re = SANITIZER[ruleId];
  return name && re && re.test(name) ? name : null;
}

/**
 * Whether `node` is — or resolves through local variables to — a recognized sanitizer call for
 * `ruleId`. Handles both `el.innerHTML = DOMPurify.sanitize(x)` and the aliased form
 * `const clean = DOMPurify.sanitize(x); el.innerHTML = clean`. Returns the sanitizer name or null.
 */
export function resolvesToSanitizer(
  node: AstNode | null | undefined,
  ruleId: string,
  ctx: RuleContext,
  seen: Set<string> = new Set()
): string | null {
  if (!node) return null;
  const direct = isSanitizerCall(node, ruleId);
  if (direct) return direct;
  const n = node as Record<string, any>;
  if (n.type === "AwaitExpression") return resolvesToSanitizer(n.argument as AstNode, ruleId, ctx, seen);
  if (n.type === "Identifier" && ctx.ast && !seen.has(n.name)) {
    seen.add(n.name);
    const init = declInit(n.name, ctx.ast);
    return init ? resolvesToSanitizer(init, ruleId, ctx, seen) : null;
  }
  return null;
}

// --- secret-finding precision ----------------------------------------------

/** Shannon entropy in bits per character. */
export function shannonEntropy(s: string): number {
  if (!s) return 0;
  const freq: Record<string, number> = {};
  for (const ch of s) freq[ch] = (freq[ch] || 0) + 1;
  let e = 0;
  for (const k of Object.keys(freq)) {
    const p = freq[k] / s.length;
    e -= p * Math.log2(p);
  }
  return e;
}

const PLACEHOLDER_RE =
  /^(?:change[_-]?me|change[_-]?this|password|passwd|pwd|secret|token|apikey|api[_-]?key|example(?:key)?|sample|test(?:ing)?|dummy|fake|placeholder|redacted|none|null|undefined|todo|foo(?:bar)?|xxx+|your[_-].*|my[_-].*|<.*>|\.{3,}|\*{3,})$/i;

const KNOWN_TOKEN_RE =
  /AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{40,}|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_\-]{35}|sk_live_[0-9a-zA-Z]{16,}|-----BEGIN/;

export interface SecretVerdict {
  /** Drop this match — it's a placeholder / env reference / low-entropy constant, not a real secret. */
  skip?: boolean;
  /** Confidence note appended to the finding message. */
  note?: string;
}

/**
 * Decide whether a `hardcoded-secret` regex hit is a real credential, an env/placeholder reference
 * to drop, or a generic value to keep. Conservative: anything matching a known provider key format
 * is always kept; only obvious non-secrets are skipped.
 */
export function classifySecret(matchText: string): SecretVerdict {
  if (KNOWN_TOKEN_RE.test(matchText)) {
    return { note: "matches a known provider key format — high confidence" };
  }
  // Reference to an env var / interpolation is configuration, not a committed secret.
  if (/\$\{|process\.env|import\.meta\.env|os\.environ|getenv/i.test(matchText)) return { skip: true };

  const m = matchText.match(/["']([^"'\n]{6,})["']/);
  const value = (m ? m[1] : matchText).trim();
  if (PLACEHOLDER_RE.test(value)) return { skip: true };
  // Short, low-entropy constants (e.g. "letmein1") are almost always fixtures, not live keys.
  if (value.length < 12 && shannonEntropy(value) < 3) return { skip: true };
  return {};
}

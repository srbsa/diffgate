// JS/TS call-graph extraction. JS/TS files aren't tree-sitter-parsed in this build (no grammar in
// GRAMMAR_PACKAGES) — they already have a Babel AST via parsers/javascript.ts, so we walk that
// instead. Mirrors the shape (FnDef/CallSite) the tree-sitter profiles in callgraph.ts produce, so
// buildCallGraph can merge both into one graph.
import type { AstNode } from "../types.js";
import { walk, memberName } from "../parsers/javascript.js";
import type { FnDef, CallSite } from "./callgraph.js";

const FN_DEF_TYPES = new Set(["FunctionDeclaration", "ClassMethod", "ClassPrivateMethod", "ObjectMethod"]);
/** Type declarations, tracked separately from functions so `impact()` can tell a genuinely
 *  uncalled class from two same-named classes whose call sites got conflated by bare-name matching. */
const TYPE_DECL_TYPES = new Set(["ClassDeclaration", "TSInterfaceDeclaration"]);

function nodeLine(node: AstNode, which: "start" | "end"): number {
  const loc = (node as unknown as { loc?: { start: { line: number }; end: { line: number } } }).loc;
  return loc ? loc[which].line : 0;
}

/** Name bound to a node, when it's a named function/method def or a function/arrow expression
 *  assigned to a simple binding (`const f = () => {}`, `foo = function () {}`, a class field arrow). */
function declaredName(node: AstNode, parent: AstNode | null): string | null {
  const n = node as unknown as { id?: { name?: string }; key?: { type?: string; name?: string; id?: { name?: string } } };
  if (FN_DEF_TYPES.has(node.type)) {
    if (node.type === "FunctionDeclaration") return n.id?.name ?? null;
    if (n.key?.type === "Identifier") return n.key.name ?? null;
    if (n.key?.type === "PrivateName") return n.key.id?.name ?? null;
    return null;
  }
  if (node.type === "FunctionExpression" || node.type === "ArrowFunctionExpression") {
    const p = parent as unknown as {
      type?: string;
      id?: { type?: string; name?: string };
      key?: { type?: string; name?: string };
      left?: AstNode & { name?: string; computed?: boolean };
    } | null;
    if (!p) return null;
    if (p.type === "VariableDeclarator" && p.id?.type === "Identifier") return p.id.name ?? null;
    if ((p.type === "ClassProperty" || p.type === "PropertyDefinition") && p.key?.type === "Identifier") return p.key.name ?? null;
    if (p.type === "AssignmentExpression" && p.left?.type === "Identifier") return (p.left as { name?: string }).name ?? null;
    if (p.type === "AssignmentExpression" && p.left?.type === "MemberExpression" && !p.left.computed) {
      const full = memberName(p.left as AstNode);
      return full ? full.split(".").pop() || null : null;
    }
    return null;
  }
  return null;
}

/** Bare callee name for a call/new expression: the identifier, or the rightmost property of a
 *  non-computed member access (`obj.foo()` → "foo") — same bare-name convention the tree-sitter
 *  profiles use, so cross-language lookups stay consistent (at the same confidence level). */
function calleeBareName(node: AstNode): string | null {
  const callee = (node as unknown as { callee?: AstNode & { name?: string; computed?: boolean } }).callee;
  if (!callee) return null;
  if (callee.type === "Identifier") return callee.name ?? null;
  if (callee.type === "MemberExpression" && !callee.computed) {
    const full = memberName(callee);
    return full ? full.split(".").pop() || null : null;
  }
  return null;
}

/**
 * Extract function/method definitions and call sites from a JS/TS Babel AST in one pass. `walk`
 * only exposes the immediate parent per node, so the enclosing-function name is threaded through
 * a node→name map built in the same pre-order traversal (parent is always visited before its
 * children, so the map entry is ready by the time we reach them).
 */
export function extractJs(root: AstNode, file: string): { fns: FnDef[]; sites: CallSite[]; types: FnDef[] } {
  const fns: FnDef[] = [];
  const sites: CallSite[] = [];
  const types: FnDef[] = [];
  const enclosing = new Map<AstNode, string>();
  enclosing.set(root, "<top-level>");

  walk(root, (node, parent) => {
    const parentEnclosing = (parent && enclosing.get(parent)) || "<top-level>";
    const name = declaredName(node, parent);
    enclosing.set(node, name || parentEnclosing);

    if (name) {
      fns.push({ name, qualName: name, file, startLine: nodeLine(node, "start"), endLine: nodeLine(node, "end"), language: "javascript" });
    }

    if (TYPE_DECL_TYPES.has(node.type)) {
      const typeName = (node as unknown as { id?: { name?: string } }).id?.name;
      if (typeName) {
        types.push({ name: typeName, qualName: typeName, file, startLine: nodeLine(node, "start"), endLine: nodeLine(node, "end"), language: "javascript" });
      }
    }

    if (node.type === "CallExpression" || node.type === "NewExpression") {
      const calleeName = calleeBareName(node);
      if (calleeName) {
        sites.push({ calleeName, callerQualName: parentEnclosing, file, line: nodeLine(node, "start") });
      }
    }
  });

  return { fns, sites, types };
}

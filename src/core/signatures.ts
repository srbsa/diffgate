import type { AstNode } from "./types.js";

interface SigEntry {
  params: string[];
  loc: { start: { line: number; column: number }; end?: { line: number; column: number } };
}

function paramSig(p: AstNode | null | undefined): string {
  if (!p) return "_";
  switch (p.type) {
    case "Identifier":
      return (p.name as string) + (p.optional ? "?" : "");
    case "AssignmentPattern":
      return paramSig(p.left as AstNode) + "=";
    case "RestElement":
      return "..." + paramSig(p.argument as AstNode);
    case "ObjectPattern":
      return "{…}";
    case "ArrayPattern":
      return "[…]";
    case "TSParameterProperty":
      return paramSig(p.parameter as AstNode);
    default:
      return (p.name as string) || "_";
  }
}

function addDecl(decl: AstNode | null | undefined, map: Map<string, SigEntry>): void {
  if (!decl) return;
  if (decl.type === "FunctionDeclaration" && decl.id) {
    const id = decl.id as AstNode;
    map.set(id.name as string, {
      params: (decl.params as AstNode[]).map(paramSig),
      loc: decl.loc as SigEntry["loc"],
    });
  } else if (decl.type === "VariableDeclaration") {
    for (const d of decl.declarations as AstNode[]) {
      const id = d.id as AstNode | undefined;
      const init = d.init as AstNode | undefined;
      if (
        id && id.type === "Identifier" && init &&
        (init.type === "ArrowFunctionExpression" || init.type === "FunctionExpression")
      ) {
        map.set(id.name as string, {
          params: (init.params as AstNode[]).map(paramSig),
          loc: d.loc as SigEntry["loc"],
        });
      }
    }
  }
}

export function collectExportedSignatures(ast: AstNode): Map<string, SigEntry> {
  const map = new Map<string, SigEntry>();
  const program = (ast.program as AstNode) || ast;
  const body = (program.body as AstNode[]) || [];
  for (const node of body) {
    if (node.type === "ExportNamedDeclaration" && node.declaration) {
      addDecl(node.declaration as AstNode, map);
    } else if (node.type === "ExportDefaultDeclaration") {
      const d = node.declaration as AstNode;
      if (d && (d.type === "FunctionDeclaration" || d.type === "ArrowFunctionExpression" || d.type === "FunctionExpression")) {
        const name = (d.id as AstNode | undefined)?.name as string | undefined || "default";
        map.set(name, {
          params: (d.params as AstNode[]).map(paramSig),
          loc: d.loc as SigEntry["loc"],
        });
      }
    }
  }
  return map;
}

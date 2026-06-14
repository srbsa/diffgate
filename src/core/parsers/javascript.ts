import { parse as babelParse } from "@babel/parser";
import type { AstNode } from "../types.js";

const PLUGINS_BASE: string[] = [
  "jsx",
  "decorators-legacy",
  "classProperties",
  "classPrivateProperties",
  "classPrivateMethods",
  "classStaticBlock",
  "importAssertions",
  "explicitResourceManagement",
];

export function parseJs(content: string, language: string): AstNode {
  const plugins = [...PLUGINS_BASE] as NonNullable<Parameters<typeof babelParse>[1]>["plugins"];
  if (language === "typescript" && plugins) plugins.push("typescript");
  return babelParse(content, {
    sourceType: "unambiguous",
    errorRecovery: true,
    allowReturnOutsideFunction: true,
    allowAwaitOutsideFunction: true,
    allowImportExportEverywhere: true,
    plugins,
  }) as unknown as AstNode;
}

const SKIP_KEYS = new Set([
  "loc", "start", "end", "range", "extra",
  "leadingComments", "trailingComments", "innerComments", "comments", "tokens",
]);

export function walk(node: AstNode, enter: (node: AstNode, parent: AstNode | null) => void, parent: AstNode | null = null): void {
  if (!node || typeof node.type !== "string") return;
  enter(node, parent);
  for (const key of Object.keys(node)) {
    if (SKIP_KEYS.has(key)) continue;
    const value = node[key];
    if (Array.isArray(value)) {
      for (const child of value) {
        if (child && typeof (child as AstNode).type === "string") walk(child as AstNode, enter, node);
      }
    } else if (value && typeof (value as AstNode).type === "string") {
      walk(value as AstNode, enter, node);
    }
  }
}

export function memberName(node: AstNode | null | undefined): string | null {
  if (!node) return null;
  if (node.type === "Identifier") return node.name as string;
  if (node.type === "ThisExpression") return "this";
  if (node.type === "MemberExpression" && !node.computed) {
    const object = memberName(node.object as AstNode);
    const prop = (node.property as AstNode)?.name as string | undefined;
    if (object && prop) return `${object}.${prop}`;
  }
  return null;
}

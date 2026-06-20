// Small per-repo state store for non-finding UX bookkeeping (kept separate from learnings.json,
// which is the team-shared verdict ledger). Currently tracks how many times the optional-CodeGraph
// adoption tip has been shown, so a one-line nudge fades out instead of nagging forever.

import fs from "fs";
import path from "path";

const DIR = ".diffgate";
const FILE = "state.json";

export interface DiffgateState {
  /** Times the "install CodeGraph for blast radius" tip has been printed in this repo. */
  graphTipShown: number;
}

const EMPTY: DiffgateState = { graphTipShown: 0 };

/** How many times the graph adoption tip may appear before it goes quiet. */
export const GRAPH_TIP_LIMIT = 3;

function statePath(root: string): string {
  return path.join(root, DIR, FILE);
}

export function loadState(root: string): DiffgateState {
  try {
    const raw = JSON.parse(fs.readFileSync(statePath(root), "utf-8"));
    if (raw && typeof raw === "object") return { ...EMPTY, ...raw };
  } catch {
    /* no state yet */
  }
  return { ...EMPTY };
}

export function saveState(root: string, state: DiffgateState): void {
  try {
    fs.mkdirSync(path.join(root, DIR), { recursive: true });
    fs.writeFileSync(statePath(root), JSON.stringify(state, null, 2) + "\n");
  } catch {
    /* best-effort — never fail a review because the tip counter couldn't be written */
  }
}

/** True while the graph tip still has shows left. */
export function shouldShowGraphTip(root: string, limit: number = GRAPH_TIP_LIMIT): boolean {
  return loadState(root).graphTipShown < limit;
}

/** Record that the graph tip was shown once. */
export function recordGraphTipShown(root: string): void {
  const state = loadState(root);
  saveState(root, { ...state, graphTipShown: state.graphTipShown + 1 });
}

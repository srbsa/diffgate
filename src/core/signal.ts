// Signal-vs-noise measurement. Two views:
//  - predicted: from a review's tier mix (orange/yellow = signal, green = noise-ish).
//  - realized:  from reviewer verdicts in .diffgate/learnings.json (confirm vs dismiss) — ground truth.
//
// Framing follows the low-noise-review framework: signal = (T1 critical + T2 important) / total.
// Realized signal turns the learnings store into a defensible adoption metric and surfaces
// chronically-dismissed rules so a team can prune noise at the source.

import type { TierCounts } from "./types.js";
import type { LearningStore } from "./learnings.js";

export interface PredictedSignal {
  /** T1 critical (orange / blocking). */
  t1: number;
  /** T2 important (yellow). */
  t2: number;
  /** T3 low-signal (green). */
  t3: number;
  total: number;
  /** (t1 + t2) / total. 1 when there are no findings. */
  ratio: number;
}

export function predictedSignal(counts: TierCounts): PredictedSignal {
  const t1 = counts.orange || 0;
  const t2 = counts.yellow || 0;
  const t3 = counts.green || 0;
  const total = t1 + t2 + t3;
  return { t1, t2, t3, total, ratio: total === 0 ? 1 : (t1 + t2) / total };
}

export interface RuleSignal {
  ruleId: string;
  confirmed: number;
  dismissed: number;
  total: number;
  /** dismissed / total — how noisy this rule has been for the team. */
  dismissRate: number;
}

export interface RealizedSignal {
  confirmed: number;
  dismissed: number;
  total: number;
  /** confirmed / total — share of verdicted findings that were real catches. 1 when no verdicts. */
  signalRatio: number;
  /** Per-rule breakdown, noisiest first. */
  byRule: RuleSignal[];
  /** Rules dismissed often enough to recommend disabling/re-tiering. */
  chronicNoise: RuleSignal[];
}

/**
 * Compute realized signal from recorded verdicts. Each learnings entry is one (rule, code)
 * pair with its latest verdict, so counting entries is correct.
 */
export function realizedSignal(
  store: LearningStore,
  opts: { minDismissals?: number; noiseThreshold?: number } = {}
): RealizedSignal {
  const minDismissals = opts.minDismissals ?? 3;
  const noiseThreshold = opts.noiseThreshold ?? 0.7;

  const byRuleMap = new Map<string, { confirmed: number; dismissed: number }>();
  let confirmed = 0;
  let dismissed = 0;
  for (const e of store.entries) {
    const r = byRuleMap.get(e.ruleId) || { confirmed: 0, dismissed: 0 };
    if (e.verdict === "confirm") {
      r.confirmed++;
      confirmed++;
    } else if (e.verdict === "dismiss") {
      r.dismissed++;
      dismissed++;
    }
    byRuleMap.set(e.ruleId, r);
  }

  const byRule: RuleSignal[] = [...byRuleMap.entries()]
    .map(([ruleId, r]) => {
      const total = r.confirmed + r.dismissed;
      return { ruleId, confirmed: r.confirmed, dismissed: r.dismissed, total, dismissRate: total === 0 ? 0 : r.dismissed / total };
    })
    .sort((a, b) => b.dismissRate - a.dismissRate || b.dismissed - a.dismissed);

  const total = confirmed + dismissed;
  const chronicNoise = byRule.filter((r) => r.dismissed >= minDismissals && r.dismissRate >= noiseThreshold);

  return {
    confirmed,
    dismissed,
    total,
    signalRatio: total === 0 ? 1 : confirmed / total,
    byRule,
    chronicNoise,
  };
}

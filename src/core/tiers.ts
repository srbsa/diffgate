import type { Tier, TierCounts, Finding } from "./types.js";

export type { Tier };

export const TIERS = {
  GREEN: "green" as Tier,
  YELLOW: "yellow" as Tier,
  ORANGE: "orange" as Tier,
};

export const TIER_ORDER: Record<string, number> = { green: 0, yellow: 1, orange: 2 };

export const TIER_META: Record<Tier, { label: string; icon: string; blurb: string; severity: string }> = {
  green: { label: "Green", icon: "🟢", blurb: "Safe / self-contained", severity: "hint" },
  yellow: { label: "Yellow", icon: "🟡", blurb: "Review — soft dependency", severity: "info" },
  orange: { label: "Orange", icon: "🟠", blurb: "High-impact — gated", severity: "warning" },
};

export function isTier(value: unknown): value is Tier {
  return value === "green" || value === "yellow" || value === "orange";
}

export function maxTier(a: string, b: string): string {
  return (TIER_ORDER[a] ?? 0) >= (TIER_ORDER[b] ?? 0) ? a : b;
}

export function overallTier(findings: Pick<Finding, "tier">[]): Tier {
  let tier: string = TIERS.GREEN;
  for (const f of findings) tier = maxTier(tier, f.tier);
  return tier as Tier;
}

export function tierCounts(findings: Pick<Finding, "tier">[]): TierCounts {
  const counts: TierCounts = { green: 0, yellow: 0, orange: 0 };
  for (const f of findings) {
    if (f.tier in counts) counts[f.tier as Tier] += 1;
  }
  return counts;
}

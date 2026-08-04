import type { Tier } from './verdicts';

export const TIER_LABELS: Record<Tier, string> = {
  critical: 'Critical',
  standard: 'Standard',
  contextual: 'Contextual',
};

/** A critical field at zero coverage fails the submission regardless of score. */
export const TIER_WEIGHTS: Record<Tier, number> = {
  critical: 3,
  standard: 2,
  contextual: 1,
};

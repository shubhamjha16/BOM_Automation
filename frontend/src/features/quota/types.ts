/** The 429 body, which is a UI state rather than an error message (S21). */
export interface QuotaRefusal {
  detail: string;
  quota: string;
  limit: number;
  used: number;
  plan: string;
  resets_at: string | null;
  retry_after_seconds: number;
  remedy: string;
}

export interface QuotaRow {
  quota: string;
  limit: number | null;
  used: number;
  remaining: number | null;
  unlimited: boolean;
}

export interface QuotaUsage {
  plan: string;
  period_start: string;
  period_end: string;
  quotas: QuotaRow[];
  components_per_submission: number | null;
  requests_per_minute: number | null;
}

export const QUOTA_LABELS: Record<string, string> = {
  submissions_per_month: 'Submissions this month',
  components_per_submission: 'Components in one submission',
  repo_generations_per_month: 'Repository generations this month',
  requests_per_minute: 'API requests per minute',
};

/**
 * A refusal, recognised structurally rather than by reading `detail`.
 *
 * The server's prose is for a human; matching on it would break the moment the
 * wording improved. Every field the state renders is checked, because a partial
 * body would otherwise render as `undefined` in front of a client.
 */
export function isQuotaRefusal(detail: unknown): detail is QuotaRefusal {
  if (typeof detail !== 'object' || detail === null) return false;
  const candidate = detail as Record<string, unknown>;
  return (
    typeof candidate.quota === 'string' &&
    typeof candidate.limit === 'number' &&
    typeof candidate.used === 'number' &&
    typeof candidate.plan === 'string' &&
    typeof candidate.remedy === 'string'
  );
}

/**
 * How much of an allowance is gone, as a fraction.
 *
 * `null` for an unlimited quota — not `0`, which a progress bar would render as
 * an empty allowance rather than as no allowance at all.
 */
export function consumedFraction(row: QuotaRow): number | null {
  if (row.unlimited || row.limit === null || row.limit === 0) return null;
  return Math.min(1, row.used / row.limit);
}

/** Approaching, so the console can warn before a client discovers a limit. */
export function isNearLimit(row: QuotaRow, threshold = 0.8): boolean {
  const fraction = consumedFraction(row);
  return fraction !== null && fraction >= threshold && fraction < 1;
}

export function isExhausted(row: QuotaRow): boolean {
  const fraction = consumedFraction(row);
  return fraction !== null && fraction >= 1;
}

/**
 * When the allowance lifts, in words.
 *
 * Returns null when nothing resets — the component quota is refused rather than
 * deferred, and telling a client to "try again later" would send them back with
 * the same 50,000-component document in a month.
 */
export function resetSentence(refusal: QuotaRefusal, now = new Date()): string | null {
  if (!refusal.resets_at) return null;
  const resets = new Date(refusal.resets_at);
  const hours = Math.round((resets.getTime() - now.getTime()) / 3_600_000);
  if (hours <= 1) return 'The allowance resets within the hour.';
  if (hours < 48) return `The allowance resets in about ${hours} hours.`;
  return `The allowance resets on ${resets.toLocaleDateString()}.`;
}

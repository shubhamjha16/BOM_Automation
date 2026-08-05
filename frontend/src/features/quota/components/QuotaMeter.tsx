import {
  QUOTA_LABELS,
  consumedFraction,
  isExhausted,
  isNearLimit,
  type QuotaRow,
} from '../types';

/**
 * One allowance, before it is exhausted.
 *
 * Exists because a limit a client discovers by hitting it is a support ticket.
 * An unlimited quota renders as "no limit" rather than as an empty bar — a bar at
 * zero reads as *no allowance*, which is the opposite of what it means.
 */
export function QuotaMeter({ row }: { row: QuotaRow }) {
  const label = QUOTA_LABELS[row.quota] ?? row.quota;
  const fraction = consumedFraction(row);
  const tone = isExhausted(row) ? 'fail' : isNearLimit(row) ? 'warn' : 'pass';

  return (
    <div className="quota-meter" data-quota={row.quota} data-tone={tone}>
      <span className="quota-meter__label">{label}</span>
      {fraction === null ? (
        <span className="quota-meter__value">No limit on this plan</span>
      ) : (
        <>
          <span className="quota-meter__value">
            {row.used.toLocaleString()} / {row.limit?.toLocaleString()}
          </span>
          <span
            className="quota-meter__bar"
            role="progressbar"
            aria-label={label}
            aria-valuenow={row.used}
            aria-valuemin={0}
            aria-valuemax={row.limit ?? undefined}
          >
            <span
              className="quota-meter__fill"
              style={{ width: `${Math.round(fraction * 100)}%` }}
            />
          </span>
        </>
      )}
    </div>
  );
}

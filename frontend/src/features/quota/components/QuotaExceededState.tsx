import { QUOTA_LABELS, resetSentence, type QuotaRefusal } from '../types';

/**
 * The screen a client sees when an allowance is exhausted.
 *
 * **A state, not an error.** Nothing here is red-alert styling or an apology:
 * the request was valid, the service is healthy, and the client has reached a
 * number they agreed to. What they need is the number, the usage, when it lifts
 * and what to do — which is exactly what the 429 body carries, so nothing is
 * invented in the console.
 *
 * Anything already assessed stays reachable. A quota screen that blocks the whole
 * console would make a billing limit look like an outage.
 */
export function QuotaExceededState({
  refusal,
  onDismiss,
}: {
  refusal: QuotaRefusal;
  onDismiss?: () => void;
}) {
  const label = QUOTA_LABELS[refusal.quota] ?? refusal.quota;
  const reset = resetSentence(refusal);

  return (
    <section className="quota-state" role="status" data-quota={refusal.quota}>
      <h2 className="quota-state__title">{label} — limit reached</h2>

      <p className="quota-state__figures">
        <strong>{refusal.used.toLocaleString()}</strong> of{' '}
        <strong>{refusal.limit.toLocaleString()}</strong> used on the{' '}
        <strong>{refusal.plan}</strong> plan.
      </p>

      {/* The server's own wording. Rewriting it here would let the console and
          the API disagree about what a client is allowed to do. */}
      <p className="quota-state__remedy">{refusal.remedy}</p>

      {reset ? (
        <p className="quota-state__reset">{reset}</p>
      ) : (
        <p className="quota-state__reset quota-state__reset--none">
          Waiting will not lift this one.
        </p>
      )}

      <p className="quota-state__reassurance">
        Assessments already completed remain available and are unaffected.
      </p>

      {onDismiss ? (
        <button type="button" className="button button--quiet" onClick={onDismiss}>
          Back to submissions
        </button>
      ) : null}
    </section>
  );
}

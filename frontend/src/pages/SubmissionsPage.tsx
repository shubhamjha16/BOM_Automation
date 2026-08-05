import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { listSubmissions } from '@/features/submissions/services/submissionsApi';
import {
  QuotaExceededState,
  QuotaMeter,
  isNearLimit,
  isQuotaRefusal,
  useQuotaUsage,
} from '@/features/quota';
import { ApiError } from '@/global/errors';
import { ROUTES } from '@/shared/constants/routes';
import { formatScore } from '@/utils/format';

export function SubmissionsPage() {
  const { data, isPending, error } = useQuery({
    queryKey: ['submissions'],
    queryFn: listSubmissions,
  });
  const usage = useQuotaUsage();

  /**
   * A 429 is a state, not a failure, so it is handled before the error branch.
   * Falling through to "Could not load submissions" would report a healthy
   * service as broken and leave the client nothing to act on.
   */
  if (error instanceof ApiError && error.isQuotaExceeded && isQuotaRefusal(error.detail)) {
    return <QuotaExceededState refusal={error.detail} />;
  }

  if (isPending) return <p>Loading submissions…</p>;
  if (error) return <p role="alert">Could not load submissions: {String(error)}</p>;

  // Shown only when an allowance is actually close. A meter on every screen at
  // 3 of 25 is furniture, and furniture is not read when it starts to matter.
  const warnRows = (usage.data?.quotas ?? []).filter((row) => isNearLimit(row));

  return (
    <section>
      <h1>Submissions</h1>

      {warnRows.length > 0 ? (
        <aside className="quota-warning" role="status">
          <p>Approaching a plan limit.</p>
          {warnRows.map((row) => (
            <QuotaMeter key={row.quota} row={row} />
          ))}
        </aside>
      ) : null}

      {data.length === 0 ? (
        <p>No submissions yet.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Received</th>
              <th>Documents</th>
              <th>Status</th>
              <th>Overall</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {data.map((submission) => (
              <tr key={submission.id}>
                <td>{new Date(submission.created_at).toLocaleString()}</td>
                <td>{submission.documents.map((d) => d.lane).join(', ') || '—'}</td>
                <td>{submission.status}</td>
                {/* Null renders as an em dash — never 0%, which is a real score. */}
                <td>{formatScore(submission.overall_score)}</td>
                <td>
                  <Link to={ROUTES.submission(submission.id)}>Open</Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

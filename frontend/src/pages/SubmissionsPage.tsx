import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { listSubmissions } from '@/features/submissions/services/submissionsApi';
import { ROUTES } from '@/shared/constants/routes';
import { formatScore } from '@/utils/format';

export function SubmissionsPage() {
  const { data, isPending, error } = useQuery({
    queryKey: ['submissions'],
    queryFn: listSubmissions,
  });

  if (isPending) return <p>Loading submissions…</p>;
  if (error) return <p role="alert">Could not load submissions: {String(error)}</p>;

  return (
    <section>
      <h1>Submissions</h1>
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

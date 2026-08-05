import { ClauseRef } from '@/components/conformance/ClauseRef';
import { useSelfScorecard, type ActivityVerdict } from '@/features/maturity';

const VERDICT_TONE: Record<string, string> = {
  met: 'badge badge--pass',
  partial: 'badge badge--warn',
  not_met: 'badge badge--fail',
  unknown: 'badge badge--neutral',
};

/**
 * Attested and evidenced are rendered differently and deliberately so. The
 * console is where the distinction is most likely to be lost — exactly as
 * `not_determinable` would have been if it were mixed into the field verdict
 * table — so an attested row carries the question that was asked, and an
 * evidenced row carries the artifact that proves it.
 */
function ActivityRow({ activity }: { activity: ActivityVerdict }) {
  const attested = activity.basis === 'attested';
  return (
    <tr className={attested ? 'attested' : undefined}>
      <td>
        <ClauseRef clause={activity.clause} />
      </td>
      <td>{activity.label}</td>
      <td>
        <span className={VERDICT_TONE[activity.verdict]}>
          {activity.verdict.replace('_', ' ')}
        </span>
      </td>
      <td>
        <span className={attested ? 'basis basis--attested' : 'basis basis--evidenced'}>
          {attested ? 'attested' : 'evidenced'}
        </span>
      </td>
      <td className="activity__detail">
        {attested ? (
          <>
            <em>Asked:</em> {activity.question}
            <br />
            <em>Answered:</em> {activity.detail}
          </>
        ) : (
          <>
            {activity.detail}
            {activity.evidence_ref && (
              <>
                <br />
                <code>{activity.evidence_ref}</code>
              </>
            )}
          </>
        )}
      </td>
    </tr>
  );
}

export function MaturityPage() {
  const { data, isPending, error } = useSelfScorecard();

  if (isPending) return <p>Assessing…</p>;
  if (error) return <p role="alert">Could not load the scorecard.</p>;

  return (
    <section>
      <h1>SSDLC maturity</h1>
      <p className="detail__meta">
        Position: <strong>{data.position}</strong> · {data.evidenced} evidenced,{' '}
        {data.attested} attested
      </p>
      <p>
        An <span className="basis basis--evidenced">evidenced</span> verdict was
        observed by the platform and names the artifact that proves it. An{' '}
        <span className="basis basis--attested">attested</span> verdict was stated in
        answer to a question. Attested is never reported as evidenced.
      </p>

      <table>
        <thead>
          <tr>
            <th>Phase</th>
            <th>Met</th>
            <th>Completion</th>
            <th>Evidenced</th>
            <th>Attested</th>
          </tr>
        </thead>
        <tbody>
          {data.phases.map((phase) => (
            <tr key={phase.phase}>
              <td>{phase.phase}</td>
              <td>
                {phase.met}/{phase.total}
              </td>
              <td>{phase.completion}%</td>
              <td>{phase.evidenced}</td>
              <td>{phase.attested}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2>Activities</h2>
      <table>
        <thead>
          <tr>
            <th>Clause</th>
            <th>Activity</th>
            <th>Verdict</th>
            <th>Basis</th>
            <th>Evidence or question</th>
          </tr>
        </thead>
        <tbody>
          {data.activities.map((activity) => (
            <ActivityRow key={activity.activity} activity={activity} />
          ))}
        </tbody>
      </table>
    </section>
  );
}

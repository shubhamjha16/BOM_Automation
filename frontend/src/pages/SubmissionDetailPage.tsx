import { useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { LaneStrip } from '@/components/conformance/LaneStrip';
import { ClauseRef } from '@/components/conformance/ClauseRef';
import { FieldVerdictBadge } from '@/components/conformance/VerdictBadge';
import {
  useCommit,
  useCorrelations,
  useFields,
  useLanes,
  useRejected,
  useSubmission,
} from '@/features/submissions';
import { LANES, type Lane } from '@/shared/constants/lanes';
import { ROUTES } from '@/shared/constants/routes';
import { formatCoverage, formatScore } from '@/utils/format';

export function SubmissionDetailPage() {
  const { id = '' } = useParams();
  const [lane, setLane] = useState<Lane>('sbom');

  const submission = useSubmission(id);
  const lanes = useLanes(id);
  const fields = useFields(id, lane);
  const rejected = useRejected(id);
  const correlations = useCorrelations(id);
  const commit = useCommit(id);

  if (submission.isPending) return <p>Loading…</p>;
  if (submission.error) return <p role="alert">Not found.</p>;

  const laneRows = lanes.data?.lanes ?? [];
  const scored = laneRows.some((row) => row.score !== null);

  return (
    <section>
      <header className="detail__head">
        <div>
          <h1>Submission</h1>
          <p className="detail__meta">
            {submission.data.documents.length} document(s) ·{' '}
            {submission.data.status} · overall {formatScore(submission.data.overall_score)}
          </p>
        </div>
        {!scored && (
          <button type="button" onClick={() => commit.mutate()} disabled={commit.isPending}>
            {commit.isPending ? 'Assessing…' : 'Run assessment'}
          </button>
        )}
      </header>

      {laneRows.length > 0 && (
        <>
          <h2>Lanes</h2>
          <LaneStrip
            lanes={laneRows.map((row) => ({
              lane: row.lane,
              verdict: row.verdict,
              score: row.score,
              entityCount: row.entity_count,
            }))}
          />
        </>
      )}

      {scored && (
        <>
          <h2>Field verdicts</h2>
          <nav className="tabs">
            {LANES.map((candidate) => (
              <button
                key={candidate}
                type="button"
                aria-pressed={candidate === lane}
                onClick={() => setLane(candidate)}
              >
                {candidate.toUpperCase()}
              </button>
            ))}
          </nav>

          {fields.error && <p>No result for this lane.</p>}
          {fields.data && (
            <>
              <table>
                <thead>
                  <tr>
                    <th>Clause</th>
                    <th>Element</th>
                    <th>Coverage</th>
                    <th>Verdict</th>
                  </tr>
                </thead>
                <tbody>
                  {fields.data.fields.map((row) => (
                    <tr key={row.element_key}>
                      <td>
                        <ClauseRef clause={row.clause} />
                      </td>
                      <td>{row.element_key}</td>
                      <td>{formatCoverage(row.populated, row.total)}</td>
                      <td>
                        <FieldVerdictBadge verdict={row.verdict} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>

              {/* Its own section, never mixed into the scored list: a consumer
                  determination is neither a pass nor a supplier defect. */}
              {fields.data.consumer_determinations.length > 0 && (
                <>
                  <h2>Consumer determinations</h2>
                  <p>
                    These cannot be established from a BOM artifact. They are excluded
                    from the supplier score and are never reported as compliant.
                  </p>
                  <dl>
                    {fields.data.consumer_determinations.map((row) => (
                      <div key={row.element_key}>
                        <dt>
                          <ClauseRef clause={row.clause} /> {row.element_key}
                        </dt>
                        <dd>{row.detail}</dd>
                        <dd>
                          <strong>Action required:</strong> {row.consumer_action}
                        </dd>
                      </div>
                    ))}
                  </dl>
                </>
              )}
            </>
          )}

          {correlations.data && correlations.data.findings.length > 0 && (
            <>
              <h2>Cross-BOM findings</h2>
              <p>Findings no single-lane assessment could produce.</p>
              <ul>
                {correlations.data.findings.map((finding) => (
                  <li key={finding.rule_key}>
                    <ClauseRef clause={finding.clause} /> <strong>{finding.rule_key}</strong>{' '}
                    <span className={`badge badge--${finding.severity === 'critical' ? 'fail' : 'warn'}`}>
                      {finding.severity}
                    </span>
                    <p>{finding.detail}</p>
                  </li>
                ))}
              </ul>
            </>
          )}

          {rejected.data && (
            <>
              <h2>Ingestion</h2>
              <p>
                {rejected.data.totals.received} entries received ·{' '}
                {rejected.data.totals.parsed} parsed · {rejected.data.totals.rejected}{' '}
                rejected. Nothing is dropped silently.
              </p>
              {rejected.data.rejected.length > 0 && (
                <table>
                  <thead>
                    <tr>
                      <th>Lane</th>
                      <th>Entry</th>
                      <th>Reason</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rejected.data.rejected.map((entry) => (
                      <tr key={`${entry.lane}-${entry.ord}`}>
                        <td>{entry.lane}</td>
                        <td>#{entry.ord}</td>
                        <td>{entry.reason}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </>
          )}
        </>
      )}

      <p className="detail__links">
        <Link to="/submissions">← All submissions</Link>
        {scored && <Link to={ROUTES.assessment(id)}>View assessment →</Link>}
      </p>
    </section>
  );
}

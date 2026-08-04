/** Mirrors `backend/app/configs/jobTypes.py`. */

export const JOB_TYPES = [
  'assess_submission',
  'rescore_submission',
  'narrative_gap_report',
  'narrative_roadmap',
  'narrative_advisory',
  'vex_draft_justification',
  'vex_csaf_export',
] as const;
export type JobType = (typeof JOB_TYPES)[number];

export const JOB_STATUSES = [
  'queued',
  'running',
  'succeeded',
  'failed',
  'blocked_conformance',
] as const;
export type JobStatus = (typeof JOB_STATUSES)[number];

export const TERMINAL_STATUSES: readonly JobStatus[] = [
  'succeeded',
  'failed',
  'blocked_conformance',
];

/**
 * `blocked_conformance` is not a crash and must not render as one: the engine
 * refused to issue an assessment it could not trace to a clause. Showing it as a
 * generic error invites a retry, which will correctly refuse again.
 */
export const JOB_STATUS_LABELS: Record<JobStatus, string> = {
  queued: 'Queued',
  running: 'Running',
  succeeded: 'Complete',
  failed: 'Failed',
  blocked_conformance: 'Blocked — untraceable clause reference',
};

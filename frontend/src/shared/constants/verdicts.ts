/**
 * Mirrors `backend/app/configs/jobTypes.py`. S3 generates these from the OpenAPI
 * schema into `packages/api-types` and a drift between the two fails CI; until
 * then `tests/constants.test.ts` checks them against the running backend.
 */

export const FIELD_VERDICTS = ['present', 'absent', 'not_determinable'] as const;
export type FieldVerdict = (typeof FIELD_VERDICTS)[number];

export const LANE_VERDICTS = [
  'pass',
  'conditional',
  'fail',
  'lane_absent',
  'lane_timeout',
  'lane_not_applicable',
] as const;
export type LaneVerdict = (typeof LANE_VERDICTS)[number];

/**
 * `lane_not_applicable` is excluded from the overall score; `lane_absent` is a
 * finding. Rendering them the same way is the single most likely way for this
 * distinction to be lost between the engine and the reader, so the styling is
 * derived from the verdict rather than chosen per screen.
 */
export const LANE_VERDICT_PRESENTATION: Record<
  LaneVerdict,
  { label: string; tone: 'pass' | 'warn' | 'fail' | 'neutral'; isFinding: boolean }
> = {
  pass: { label: 'Conformant', tone: 'pass', isFinding: false },
  conditional: { label: 'Conditional', tone: 'warn', isFinding: true },
  fail: { label: 'Non-conformant', tone: 'fail', isFinding: true },
  lane_absent: { label: 'Not declared', tone: 'fail', isFinding: true },
  lane_timeout: { label: 'Assessment timed out', tone: 'warn', isFinding: true },
  lane_not_applicable: { label: 'Not applicable', tone: 'neutral', isFinding: false },
};

/**
 * `not_determinable` is never `compliant`. It renders in its own section with the
 * consumer action required — never as a pass, never as a supplier defect.
 */
export const FIELD_VERDICT_PRESENTATION: Record<
  FieldVerdict,
  { label: string; tone: 'pass' | 'fail' | 'neutral'; countsAgainstSupplier: boolean }
> = {
  present: { label: 'Present', tone: 'pass', countsAgainstSupplier: false },
  absent: { label: 'Absent', tone: 'fail', countsAgainstSupplier: true },
  not_determinable: {
    label: 'Consumer determination',
    tone: 'neutral',
    countsAgainstSupplier: false,
  },
};

export const TIERS = ['critical', 'standard', 'contextual'] as const;
export type Tier = (typeof TIERS)[number];

export const DETERMINABILITY = ['auto', 'enrich', 'human'] as const;
export type Determinability = (typeof DETERMINABILITY)[number];

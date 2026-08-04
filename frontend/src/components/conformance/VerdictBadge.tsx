import type { FieldVerdict, LaneVerdict } from '@/shared/constants/verdicts';
import {
  FIELD_VERDICT_PRESENTATION,
  LANE_VERDICT_PRESENTATION,
} from '@/shared/constants/verdicts';

const TONE_CLASS = {
  pass: 'badge badge--pass',
  warn: 'badge badge--warn',
  fail: 'badge badge--fail',
  neutral: 'badge badge--neutral',
} as const;

export function LaneVerdictBadge({ verdict }: { verdict: LaneVerdict }) {
  const meta = LANE_VERDICT_PRESENTATION[verdict];
  return (
    <span className={TONE_CLASS[meta.tone]} data-verdict={verdict}>
      {meta.label}
    </span>
  );
}

export function FieldVerdictBadge({ verdict }: { verdict: FieldVerdict }) {
  const meta = FIELD_VERDICT_PRESENTATION[verdict];
  return (
    <span className={TONE_CLASS[meta.tone]} data-verdict={verdict}>
      {meta.label}
    </span>
  );
}

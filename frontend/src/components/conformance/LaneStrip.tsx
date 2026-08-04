import type { Lane } from '@/shared/constants/lanes';
import { LANE_META, PROCUREMENT_SOURCED_LANES } from '@/shared/constants/lanes';
import type { LaneVerdict } from '@/shared/constants/verdicts';
import { LaneVerdictBadge } from './VerdictBadge';
import { ScoreDial } from './ScoreDial';

export interface LaneSummary {
  lane: Lane;
  verdict: LaneVerdict;
  score: number | null;
  entityCount: number;
}

/** Five lanes side by side — five tracks, not one spinner. */
export function LaneStrip({ lanes }: { lanes: LaneSummary[] }) {
  return (
    <ul className="lane-strip">
      {lanes.map((lane) => (
        <li key={lane.lane} className="lane-strip__item">
          <h3>{LANE_META[lane.lane].label}</h3>
          <ScoreDial score={lane.score} label={`${lane.entityCount} entities`} />
          <LaneVerdictBadge verdict={lane.verdict} />
          {PROCUREMENT_SOURCED_LANES.includes(lane.lane) && (
            <p className="lane-strip__note">
              Procurement-sourced: from asset registers and purchase records, not a scan.
            </p>
          )}
        </li>
      ))}
    </ul>
  );
}

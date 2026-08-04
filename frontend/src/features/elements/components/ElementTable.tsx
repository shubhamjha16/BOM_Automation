import { ClauseRef } from '@/components/conformance/ClauseRef';
import { TIER_LABELS } from '@/shared/constants/tiers';
import type { MinimumElement } from '../services/elementsApi';

/**
 * The catalogue, readable. A client checking our encoding against the published
 * PDF is the point — so consumer determinations are separated out here rather
 * than mixed into the scored list, exactly as they are in the assessment.
 */
export function ElementTable({ elements }: { elements: MinimumElement[] }) {
  const scored = elements.filter((element) => element.scores_against_supplier);
  const determined = elements.filter((element) => !element.scores_against_supplier);

  return (
    <>
      <h2>Supplier-scored elements ({scored.length})</h2>
      <table>
        <thead>
          <tr>
            <th>Clause</th>
            <th>Element</th>
            <th>Tier</th>
            <th>Source</th>
          </tr>
        </thead>
        <tbody>
          {scored.map((element) => (
            <tr key={element.key}>
              <td>
                <ClauseRef clause={element.clause} />
              </td>
              <td>{element.label}</td>
              <td>{TIER_LABELS[element.tier]}</td>
              <td>{element.determinability}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2>Consumer determinations ({determined.length})</h2>
      <p>
        These cannot be established from a BOM artifact. They are excluded from the
        supplier score and are never reported as compliant.
      </p>
      <dl>
        {determined.map((element) => (
          <div key={element.key}>
            <dt>
              <ClauseRef clause={element.clause} /> {element.label}
            </dt>
            <dd>{element.rationale}</dd>
            <dd>
              <strong>Action required:</strong> {element.consumer_action}
            </dd>
          </div>
        ))}
      </dl>
    </>
  );
}

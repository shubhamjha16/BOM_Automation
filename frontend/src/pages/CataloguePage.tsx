import { useState } from 'react';
import { ElementTable, useElements } from '@/features/elements';
import { LANES, LANE_META, type Lane } from '@/shared/constants/lanes';

/**
 * The encoded catalogue, inspectable. A conformance engine whose rules cannot be
 * read is asking to be trusted rather than verified.
 */
export function CataloguePage() {
  const [lane, setLane] = useState<Lane>('sbom');
  const { data, isPending, error } = useElements(lane);

  return (
    <section>
      <h1>Minimum elements</h1>
      <nav className="tabs">
        {LANES.map((candidate) => (
          <button
            key={candidate}
            type="button"
            aria-pressed={candidate === lane}
            onClick={() => setLane(candidate)}
          >
            {LANE_META[candidate].label}
          </button>
        ))}
      </nav>

      {isPending && <p>Loading…</p>}
      {error && <p role="alert">Could not load the catalogue.</p>}
      {data && (
        <>
          <p>
            {data.guideline.ref} v{data.guideline.version} ({data.guideline.published_on}) ·
            checksum <code>{data.catalogue_checksum.slice(0, 12)}</code>
          </p>
          {data.element_count === 0 ? (
            <p>
              This lane's catalogue is not yet encoded, so the lane reports{' '}
              <strong>not declared</strong> rather than a score. Approximating the table
              would produce a score against invented clauses.
            </p>
          ) : (
            <ElementTable elements={data.elements} />
          )}
        </>
      )}
    </section>
  );
}

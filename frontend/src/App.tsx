import { useState } from 'react';
import { ElementTable, useElements } from '@/features/elements';
import { LANES, LANE_META, type Lane } from '@/shared/constants/lanes';

/**
 * S1 ships one real screen: the encoded catalogue, inspectable. It is the screen
 * that proves the engine's rules can be read rather than trusted, and it needs no
 * auth, no database and no submission to be useful.
 */
export default function App() {
  const [lane, setLane] = useState<Lane>('sbom');
  const { data, isPending, error } = useElements(lane);

  return (
    <main>
      <header>
        <h1>BOM Factory</h1>
        <p>CERT-In conformance assessment. Not a legal opinion.</p>
        <nav>
          {LANES.map((candidate) => (
            <button
              key={candidate}
              onClick={() => setLane(candidate)}
              aria-pressed={candidate === lane}
            >
              {LANE_META[candidate].label}
            </button>
          ))}
        </nav>
      </header>

      {isPending && <p>Loading the catalogue…</p>}
      {error && <p role="alert">Could not load the catalogue: {String(error)}</p>}
      {data && (
        <section>
          <p>
            {data.guideline.ref} v{data.guideline.version} ({data.guideline.published_on}) ·
            catalogue checksum <code>{data.catalogue_checksum.slice(0, 12)}</code>
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
        </section>
      )}
    </main>
  );
}

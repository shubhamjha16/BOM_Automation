import { useState } from 'react';
import { useNarrative } from '../hooks/useNarrative';
import { countPlaceholders, splitPlaceholders, type HousePassage } from '../types';

const SECTIONS = ['Licence coverage', 'Supplier identification', 'Cryptographic declarations'];

/**
 * The drafted section, beside the house wording it drew on.
 *
 * **Both halves are shown deliberately.** A drafted paragraph on its own is
 * unfalsifiable — a reader cannot tell whether the voice came from the firm's own
 * past work or from the model, nor whether any figure in it was earned. The
 * fact-masked sources next to it make both checkable.
 */
export function NarrativePanel({ submissionId }: { submissionId: string }) {
  const [section, setSection] = useState<string | null>(null);
  const { data, isFetching, error } = useNarrative(submissionId, section ?? '', section !== null);

  return (
    <section className="narrative">
      <h2>Narrative drafting</h2>
      <p className="narrative__lede">
        Retrieval draws on this firm's own past wording, scoped to this tenant and
        stripped of every figure before it is stored. The engine supplies the facts;
        the model may only restate them.
      </p>

      <div className="tabs">
        {SECTIONS.map((name) => (
          <button
            key={name}
            type="button"
            aria-pressed={section === name}
            onClick={() => setSection(name)}
          >
            {name}
          </button>
        ))}
      </div>

      {section === null ? (
        <p className="narrative__idle">Choose a section to draft.</p>
      ) : isFetching ? (
        <p className="narrative__idle">Retrieving house wording and drafting…</p>
      ) : error ? (
        <p role="alert">Could not draft this section: {String(error)}</p>
      ) : data ? (
        <>
          {data.refused ? (
            <div className="narrative__refused" role="status">
              <strong>Draft refused.</strong> {data.reason}
            </div>
          ) : (
            <article
              className={data.drafted ? 'narrative__draft' : 'narrative__draft narrative__draft--undrafted'}
            >
              <header className="narrative__badge">
                {data.drafted ? (
                  <span className="basis basis--evidenced">drafted by {data.generator}</span>
                ) : (
                  <span className="basis basis--attested">
                    not drafted — findings restated by the engine
                  </span>
                )}
              </header>
              <p className="narrative__body">{data.content}</p>
            </article>
          )}

          <Sources passages={data.retrieval?.passages ?? []} empty={data.retrieval?.corpus_empty} />

          <details className="narrative__facts">
            <summary>
              Facts supplied to the model ({(data.facts ?? data.supplied_facts ?? []).length})
            </summary>
            <ul>
              {(data.facts ?? data.supplied_facts ?? []).map((fact) => (
                <li key={fact}>{fact}</li>
              ))}
            </ul>
            <p className="narrative__note">
              Every figure and clause the draft may contain comes from this list. One
              that does not is refused, not warned about.
            </p>
          </details>
        </>
      ) : null}
    </section>
  );
}

function Sources({ passages, empty }: { passages: HousePassage[]; empty?: boolean }) {
  if (empty) {
    return (
      <p className="narrative__idle">
        No house wording in this tenant's corpus yet — the draft used plain professional
        prose rather than inventing a style.
      </p>
    );
  }
  if (passages.length === 0) return null;

  const masked = passages.reduce((total, p) => total + countPlaceholders(p.content), 0);

  return (
    <div className="narrative__sources">
      <h3>
        House wording retrieved ({passages.length}) —{' '}
        <span className="narrative__masked-count">{masked} figures masked</span>
      </h3>
      <p className="narrative__note">
        Retrieved from this tenant only. Every figure, clause reference and identifier
        was replaced with a typed placeholder <em>before</em> the passage was stored, so
        no other engagement's number is in the prompt to be copied.
      </p>
      {passages.map((passage) => (
        <figure key={passage.title + passage.content.slice(0, 24)} className="passage">
          <figcaption>
            <strong>{passage.title}</strong>
            <span className="passage__kind">{passage.kind.replace(/_/g, ' ')}</span>
            <span className="passage__found">
              found by {passage.found_by.join(' + ')}
            </span>
          </figcaption>
          <blockquote>
            {splitPlaceholders(passage.content).map((part, index) =>
              part.placeholder ? (
                <mark key={index} className="masked" title="A figure was removed here">
                  {part.text}
                </mark>
              ) : (
                <span key={index}>{part.text}</span>
              ),
            )}
          </blockquote>
        </figure>
      ))}
    </div>
  );
}

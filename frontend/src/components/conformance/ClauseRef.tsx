import { formatClause, GUIDELINE_REF } from '@/utils/clause';

/**
 * Every clause reference in the console carries the guideline version it resolves
 * against. A bare "4.2(5)" is meaningless once v3.0 publishes.
 */
export function ClauseRef({ clause }: { clause: string }) {
  return (
    <abbr className="clause-ref" title={GUIDELINE_REF} data-clause={clause}>
      {formatClause(clause)}
    </abbr>
  );
}

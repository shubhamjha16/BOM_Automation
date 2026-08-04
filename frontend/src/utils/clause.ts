/**
 * Clause parsing and presentation.
 *
 * Every verdict in the console must be clickable through to the guideline clause
 * behind it — that traceability is the product, which is why this lives in shared
 * utils rather than inside one feature.
 */

export const GUIDELINE_REF =
  'CERT-In Technical Guidelines on SBOM, QBOM & CBOM, AIBOM and HBOM v2.0 (09.07.2025)';

const CLAUSE_PATTERN = /^(\d+(?:\.\d+)*)(?:\((\d+)\))?$/;

export interface ParsedClause {
  section: string;
  ordinal: number | null;
}

/** Returns null for anything that is not a clause — never a guess. */
export function parseClause(clause: string): ParsedClause | null {
  const match = CLAUSE_PATTERN.exec(clause.trim());
  if (!match) return null;
  return { section: match[1], ordinal: match[2] ? Number(match[2]) : null };
}

export function formatClause(clause: string): string {
  const parsed = parseClause(clause);
  if (!parsed) return clause;
  return parsed.ordinal === null
    ? `s.${parsed.section}`
    : `s.${parsed.section}(${parsed.ordinal})`;
}

/** Sorts clause references in document order rather than lexically. */
export function compareClauses(left: string, right: string): number {
  const a = parseClause(left);
  const b = parseClause(right);
  if (!a || !b) return left.localeCompare(right);

  const aParts = a.section.split('.').map(Number);
  const bParts = b.section.split('.').map(Number);
  for (let i = 0; i < Math.max(aParts.length, bParts.length); i += 1) {
    const diff = (aParts[i] ?? 0) - (bParts[i] ?? 0);
    if (diff !== 0) return diff;
  }
  return (a.ordinal ?? 0) - (b.ordinal ?? 0);
}

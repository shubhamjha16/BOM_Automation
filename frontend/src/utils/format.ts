/**
 * A score is never invented in the console. `null` means the engine did not
 * produce one — an unimplemented lane, a lane the engagement disabled, a
 * timeout — and it renders as an em dash, never as 0%.
 */
export function formatScore(score: number | null | undefined): string {
  return score === null || score === undefined ? '—' : `${score.toFixed(1)}%`;
}

export function formatCoverage(populated: number, total: number): string {
  if (total === 0) return 'no entities';
  return `${populated} of ${total} (${((populated / total) * 100).toFixed(1)}%)`;
}

/** Mirrors `backend/app/configs/laneConfig.py`. */

export const LANES = ['sbom', 'cbom', 'qbom', 'aibom', 'hbom'] as const;
export type Lane = (typeof LANES)[number];

export const LANE_META: Record<Lane, { label: string; clauseRoot: string; sprint: string }> = {
  sbom: { label: 'Software BOM', clauseRoot: '4.2', sprint: 'S1' },
  aibom: { label: 'AI BOM', clauseRoot: '9.3', sprint: 'S1' },
  cbom: { label: 'Cryptography BOM', clauseRoot: '8.4', sprint: 'S14' },
  qbom: { label: 'Quantum BOM', clauseRoot: '8.5', sprint: 'S14' },
  hbom: { label: 'Hardware BOM', clauseRoot: '10.2', sprint: 'S16' },
};

/**
 * HBOM data is procurement data — asset registers and purchase records, not
 * scanner output. The console labels it so a reader can tell which claims rest
 * on a scan and which on a purchase order.
 */
export const PROCUREMENT_SOURCED_LANES: readonly Lane[] = ['hbom'];

import { apiClient } from '@/global/apiClient';
import type { Lane } from '@/shared/constants/lanes';
import type { Determinability, Tier } from '@/shared/constants/verdicts';

export interface MinimumElement {
  key: string;
  label: string;
  clause: string;
  tier: Tier;
  determinability: Determinability;
  /** 'entity' = per component; 'document' = a property of the BOM document. */
  scope: 'entity' | 'document';
  scores_against_supplier: boolean;
  rationale: string | null;
  consumer_action: string | null;
}

export interface ElementsResponse {
  lane: Lane;
  clause_root: string;
  guideline: { ref: string; version: string; published_on: string };
  catalogue_checksum: string;
  element_count: number;
  supplier_scored_count: number;
  consumer_determined_count: number;
  elements: MinimumElement[];
}

export const fetchElements = (lane: Lane) =>
  apiClient.get<ElementsResponse>(`/elements?lane=${lane}`);

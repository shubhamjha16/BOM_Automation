export interface HousePassage {
  title: string;
  kind: string;
  source_ref: string | null;
  score: number;
  found_by: string[];
  content: string;
}

export interface Retrieval {
  query: string;
  corpus_empty: boolean;
  passages: HousePassage[];
}

export interface DraftedSection {
  section: string;
  refused: boolean;
  reason?: string;
  content?: string;
  generator?: string;
  drafted?: boolean;
  facts?: string[];
  supplied_facts?: string[];
  retrieval?: Retrieval | null;
}

/**
 * Split masked text so the placeholders can be marked up.
 *
 * They are shown rather than hidden on purpose: `⟨count⟩` where a number used to
 * be is the visible proof that the passage carries this firm's sentence shape and
 * none of another client's figures.
 */
export function splitPlaceholders(text: string): { text: string; placeholder: boolean }[] {
  return text
    .split(/(⟨[a-z]+⟩)/g)
    .filter((part) => part.length > 0)
    .map((part) => ({ text: part, placeholder: /^⟨[a-z]+⟩$/.test(part) }));
}

export function countPlaceholders(text: string): number {
  return (text.match(/⟨[a-z]+⟩/g) ?? []).length;
}

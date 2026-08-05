import { useQuery } from '@tanstack/react-query';
import { narrativeApi } from '../services/narrativeApi';

/**
 * Drafting is on demand, never on page load: it costs a provider call, and a
 * reader who has not asked for prose should not be billed for it.
 */
export function useNarrative(submissionId: string, section: string, enabled: boolean) {
  return useQuery({
    queryKey: ['narrative', submissionId, section],
    queryFn: () => narrativeApi.draft(submissionId, section),
    enabled,
    staleTime: Infinity,
  });
}

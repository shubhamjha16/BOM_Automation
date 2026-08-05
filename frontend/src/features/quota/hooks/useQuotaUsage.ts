import { useQuery } from '@tanstack/react-query';
import { quotaApi } from '../services/quotaApi';

/**
 * Usage for the current tenant.
 *
 * Refetched on window focus so a long-lived tab does not show a stale allowance
 * — a client who has been submitting from CI all afternoon should not read
 * "3 of 25 used" from this morning.
 */
export function useQuotaUsage() {
  return useQuery({
    queryKey: ['quota', 'usage'],
    queryFn: quotaApi.usage,
    staleTime: 30_000,
    refetchOnWindowFocus: true,
  });
}

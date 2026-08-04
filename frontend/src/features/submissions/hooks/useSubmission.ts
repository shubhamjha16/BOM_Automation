import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { Lane } from '@/shared/constants/lanes';
import {
  commitSubmission,
  getCorrelations,
  getFields,
  getLanes,
  getRejected,
  getSubmission,
} from '../services/submissionsApi';

export const useSubmission = (id: string) =>
  useQuery({ queryKey: ['submission', id], queryFn: () => getSubmission(id) });

export const useLanes = (id: string) =>
  useQuery({ queryKey: ['lanes', id], queryFn: () => getLanes(id) });

export const useFields = (id: string, lane: Lane) =>
  useQuery({ queryKey: ['fields', id, lane], queryFn: () => getFields(id, lane) });

export const useRejected = (id: string) =>
  useQuery({ queryKey: ['rejected', id], queryFn: () => getRejected(id) });

export const useCorrelations = (id: string) =>
  useQuery({ queryKey: ['correlations', id], queryFn: () => getCorrelations(id) });

/** Commit returns a job, not an assessment — scoring is asynchronous. */
export function useCommit(id: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => commitSubmission(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['lanes', id] });
      queryClient.invalidateQueries({ queryKey: ['submission', id] });
      queryClient.invalidateQueries({ queryKey: ['rejected', id] });
      queryClient.invalidateQueries({ queryKey: ['correlations', id] });
    },
  });
}

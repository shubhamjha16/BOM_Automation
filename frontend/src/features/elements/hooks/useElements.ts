import { useQuery } from '@tanstack/react-query';
import type { Lane } from '@/shared/constants/lanes';
import { fetchElements } from '../services/elementsApi';

export function useElements(lane: Lane) {
  return useQuery({
    queryKey: ['elements', lane],
    queryFn: () => fetchElements(lane),
    // The catalogue is version-pinned data; it does not change under a session.
    staleTime: Infinity,
  });
}

import { useQuery } from '@tanstack/react-query';
import { getAssessment } from '../services/assessmentsApi';

export const useAssessment = (submissionId: string) =>
  useQuery({
    queryKey: ['assessment', submissionId],
    queryFn: () => getAssessment(submissionId),
  });

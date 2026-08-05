import { useQuery } from '@tanstack/react-query';
import { getSelfScorecard } from '../services/maturityApi';

export const useSelfScorecard = () =>
  useQuery({ queryKey: ['maturity', 'self'], queryFn: getSelfScorecard });

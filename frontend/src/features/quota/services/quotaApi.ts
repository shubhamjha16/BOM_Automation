import { apiClient } from '@/global/apiClient';
import type { QuotaUsage } from '../types';

export const quotaApi = {
  usage: () => apiClient.get<QuotaUsage>('/submissions/usage'),
};

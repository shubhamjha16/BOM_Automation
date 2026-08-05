import { apiClient } from '@/global/apiClient';
import type { DraftedSection } from '../types';

export const narrativeApi = {
  draft: (submissionId: string, section: string) =>
    apiClient.get<DraftedSection>(
      `/assessments/${submissionId}/narrative/${encodeURIComponent(section)}`,
    ),
};

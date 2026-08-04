import { apiClient } from '@/global/apiClient';
import { env } from '@/global/env';
import { useSessionStore } from '@/features/auth';

export interface AssessmentSection {
  ord: number;
  section_type: string;
  title: string;
  content: string;
  /** The provenance chain: what this section was written from. */
  field_verdict_ids: string[];
  correlation_finding_ids: string[];
}

export interface AssessmentView {
  submission_id: string;
  overall_score: number | null;
  status: string;
  /** Present until a human approves it. Never hidden from the reader. */
  watermark: string | null;
  sections: AssessmentSection[];
}

export type ExportFormat = 'json' | 'xlsx' | 'docx' | 'pdf';

export const getAssessment = (submissionId: string) =>
  apiClient.get<AssessmentView>(`/assessments/${submissionId}`);

/**
 * Downloads go through fetch rather than a plain link because the API requires
 * a bearer token — a bare href would arrive unauthenticated and 401.
 */
export async function downloadExport(
  submissionId: string,
  format: ExportFormat,
): Promise<void> {
  const token = useSessionStore.getState().accessToken;
  const response = await fetch(
    `${env.apiBaseUrl}/assessments/${submissionId}/export?format=${format}`,
    { headers: token ? { Authorization: `Bearer ${token}` } : {} },
  );

  if (!response.ok) {
    // 501 is the honest PDF case: LibreOffice absent, other formats unaffected.
    const detail = await response.json().catch(() => ({ detail: response.statusText }));
    throw new Error(detail.detail ?? 'Export failed');
  }

  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download =
    response.headers.get('Content-Disposition')?.match(/filename="(.+)"/)?.[1] ??
    `assessment.${format}`;
  anchor.click();
  URL.revokeObjectURL(url);
}

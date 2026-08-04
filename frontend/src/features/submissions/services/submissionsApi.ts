import { apiClient } from '@/global/apiClient';
import type { Lane } from '@/shared/constants/lanes';
import type { FieldVerdict, LaneVerdict } from '@/shared/constants/verdicts';

export interface SubmissionSummary {
  id: string;
  engagement_id: string;
  status: string;
  overall_score: number | null;
  overall_verdict: string | null;
  created_at: string;
  documents: DocumentSummary[];
}

export interface DocumentSummary {
  id: string;
  lane: Lane;
  format: string;
  filename: string | null;
  entry_count: number;
  parsed_count: number;
  rejected_count: number;
  status: string;
}

export interface LaneRollup {
  lane: Lane;
  verdict: LaneVerdict;
  score: number | null;
  entity_count: number;
  detail: string;
  counts_toward_overall: boolean;
  is_finding: boolean;
}

export interface FieldRow {
  element_key: string;
  clause: string;
  verdict: FieldVerdict;
  populated: number;
  total: number;
  coverage: number | null;
  detail: string | null;
  consumer_action: string | null;
}

export interface FieldReport {
  lane: Lane;
  score: number | null;
  verdict: LaneVerdict;
  fields: FieldRow[];
  /** not_determinable renders here — never as compliant, never as a defect. */
  consumer_determinations: FieldRow[];
}

export interface RejectedReport {
  totals: { received: number; parsed: number; rejected: number };
  documents: Array<{
    id: string;
    lane: Lane;
    filename: string | null;
    entry_count: number;
    parsed_count: number;
    rejected_count: number;
    counts_reconcile: boolean;
  }>;
  rejected: Array<{
    lane: Lane;
    ord: number;
    ref: string | null;
    reason: string;
  }>;
}

export interface CorrelationReport {
  findings: Array<{
    rule_key: string;
    severity: string;
    clause: string;
    detail: string;
  }>;
  rules: Array<{
    key: string;
    label: string;
    clause: string;
    requires: string[];
    implemented: boolean;
    rationale: string;
  }>;
}

export const listSubmissions = () => apiClient.get<SubmissionSummary[]>('/submissions');
export const getSubmission = (id: string) =>
  apiClient.get<SubmissionSummary>(`/submissions/${id}`);
export const commitSubmission = (id: string) =>
  apiClient.post<{ job_id: string; created: boolean }>(`/submissions/${id}/commit`);
export const getLanes = (id: string) =>
  apiClient.get<{ lanes: LaneRollup[] }>(`/submissions/${id}/lanes`);
export const getFields = (id: string, lane: Lane) =>
  apiClient.get<FieldReport>(`/submissions/${id}/lanes/${lane}/fields`);
export const getRejected = (id: string) =>
  apiClient.get<RejectedReport>(`/submissions/${id}/rejected`);
export const getCorrelations = (id: string) =>
  apiClient.get<CorrelationReport>(`/submissions/${id}/correlations`);

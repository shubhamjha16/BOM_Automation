import { apiClient } from '@/global/apiClient';

export type MaturityPhase = 'start' | 'progress' | 'advance';
export type MaturityVerdict = 'met' | 'partial' | 'not_met' | 'unknown';
/**
 * The distinction the whole scorecard rests on. `evidenced` means the platform
 * observed it and can point at the artifact; `attested` means somebody said so.
 * They are never rendered the same way.
 */
export type MaturityBasis = 'evidenced' | 'attested';

export interface ActivityVerdict {
  activity: string;
  clause: string;
  label: string;
  verdict: MaturityVerdict;
  basis: MaturityBasis;
  evidence_ref: string | null;
  question: string | null;
  detail: string;
}

export interface PhaseResult {
  phase: MaturityPhase;
  met: number;
  partial: number;
  not_met: number;
  unknown: number;
  total: number;
  completion: number;
  complete: boolean;
  evidenced: number;
  attested: number;
}

export interface Scorecard {
  position: string;
  phases: PhaseResult[];
  evidenced: number;
  attested: number;
  activities: ActivityVerdict[];
  gaps: ActivityVerdict[];
}

export const getSelfScorecard = () => apiClient.get<Scorecard>('/maturity/self');
export const getActivities = () =>
  apiClient.get<{ activities: unknown[]; count: number }>('/maturity/activities');

import type { Role } from '@/shared/constants/roles';

export interface Tokens {
  access_token: string;
  refresh_token: string;
  token_type: string;
  role: Role;
  org_id: string;
  user_id: string;
}

/**
 * Returned instead of tokens when a second factor is required. Carries no access
 * of any kind — `pending_token` proves only that a password was accepted.
 */
export interface MfaChallenge {
  mfa_required: true;
  enrolled: boolean;
  pending_token: string;
}

export type SignInResult = Tokens | MfaChallenge;

export const isMfaChallenge = (result: SignInResult): result is MfaChallenge =>
  'mfa_required' in result && result.mfa_required;

export interface CurrentUser {
  id: string;
  email: string;
  role: Role;
  org_id: string;
  mfa_enabled: boolean;
}

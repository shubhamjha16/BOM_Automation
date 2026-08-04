import { apiClient } from '@/global/apiClient';
import type { CurrentUser, SignInResult, Tokens } from '../types';

export const signIn = (email: string, password: string, orgId?: string) =>
  apiClient.post<SignInResult>('/auth/signin', {
    email,
    password,
    org_id: orgId ?? null,
  });

export const verifyMfa = (pendingToken: string, code: string) =>
  apiClient.post<Tokens>('/auth/mfa/verify', {
    pending_token: pendingToken,
    code,
  });

export const beginMfaEnrolment = () =>
  apiClient.post<{ secret: string; provisioning_uri: string }>('/auth/mfa/enrol');

export const confirmMfaEnrolment = (secret: string, code: string) =>
  apiClient.post<CurrentUser>('/auth/mfa/enrol/confirm', { secret, code });

export const fetchMe = () => apiClient.get<CurrentUser>('/auth/me');

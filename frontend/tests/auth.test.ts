import { beforeEach, describe, expect, it } from 'vitest';
import { useSessionStore } from '@/features/auth/store';
import { isMfaChallenge, type SignInResult } from '@/features/auth/types';
import { CAN_APPROVE } from '@/shared/constants/roles';

describe('sign-in result discrimination', () => {
  it('recognises an MFA challenge', () => {
    const challenge: SignInResult = {
      mfa_required: true,
      enrolled: true,
      pending_token: 'pending',
    };
    expect(isMfaChallenge(challenge)).toBe(true);
  });

  it('recognises real tokens', () => {
    const tokens: SignInResult = {
      access_token: 'a',
      refresh_token: 'r',
      token_type: 'bearer',
      role: 'assessor',
      org_id: 'o',
      user_id: 'u',
    };
    expect(isMfaChallenge(tokens)).toBe(false);
  });
});

describe('session store', () => {
  beforeEach(() => useSessionStore.getState().clear());

  it('starts unauthenticated', () => {
    expect(useSessionStore.getState().accessToken).toBeNull();
  });

  it('holds a session once tokens arrive', () => {
    useSessionStore.getState().setSession({
      access_token: 'a',
      refresh_token: 'r',
      token_type: 'bearer',
      role: 'manager',
      org_id: 'o1',
      user_id: 'u1',
    });
    const state = useSessionStore.getState();
    expect(state.accessToken).toBe('a');
    expect(state.role).toBe('manager');
  });

  it('clears everything on sign-out, leaving no org id behind', () => {
    useSessionStore.getState().setSession({
      access_token: 'a',
      refresh_token: 'r',
      token_type: 'bearer',
      role: 'partner',
      org_id: 'o1',
      user_id: 'u1',
    });
    useSessionStore.getState().clear();
    const state = useSessionStore.getState();
    expect(state.accessToken).toBeNull();
    expect(state.orgId).toBeNull();
    expect(state.role).toBeNull();
  });
});

describe('approval roles', () => {
  it('is manager and above only', () => {
    expect(CAN_APPROVE).toContain('manager');
    expect(CAN_APPROVE).toContain('partner');
    expect(CAN_APPROVE).not.toContain('assessor');
    expect(CAN_APPROVE).not.toContain('client');
  });
});

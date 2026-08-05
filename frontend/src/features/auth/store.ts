import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import type { Role } from '@/shared/constants/roles';
import type { Tokens } from './types';

interface SessionState {
  accessToken: string | null;
  refreshToken: string | null;
  role: Role | null;
  orgId: string | null;
  userId: string | null;
  setSession: (tokens: Tokens) => void;
  clear: () => void;
}

/**
 * The session, and only the session.
 *
 * Note what is *not* stored: the org id here is for rendering, never for
 * authorisation. Every request carries the access token and the server resolves
 * the tenant from it — a client that could choose its own org id would not be a
 * tenant boundary at all.
 */
export const useSessionStore = create<SessionState>()(
  persist(
    (set) => ({
      accessToken: null,
      refreshToken: null,
      role: null,
      orgId: null,
      userId: null,
      setSession: (tokens) =>
        set({
          accessToken: tokens.access_token,
          refreshToken: tokens.refresh_token,
          role: tokens.role,
          orgId: tokens.org_id,
          userId: tokens.user_id,
        }),
      clear: () =>
        set({
          accessToken: null,
          refreshToken: null,
          role: null,
          orgId: null,
          userId: null,
        }),
    }),
    { name: 'bom-automation-session' },
  ),
);

export const isAuthenticated = (state: SessionState) => state.accessToken !== null;

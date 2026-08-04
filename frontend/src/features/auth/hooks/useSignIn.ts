import { useState } from 'react';
import { signIn, verifyMfa } from '../services/authApi';
import { useSessionStore } from '../store';
import { isMfaChallenge, type MfaChallenge } from '../types';

/**
 * Sign-in is two steps whenever MFA is required, and the hook models that
 * explicitly rather than hiding it: a password alone never produces a session.
 */
export function useSignIn() {
  const setSession = useSessionStore((state) => state.setSession);
  const [challenge, setChallenge] = useState<MfaChallenge | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  const submitPassword = async (email: string, password: string, orgId?: string) => {
    setPending(true);
    setError(null);
    try {
      const result = await signIn(email, password, orgId);
      if (isMfaChallenge(result)) {
        setChallenge(result);
        return { mfaRequired: true as const };
      }
      setSession(result);
      return { mfaRequired: false as const };
    } catch {
      // The server deliberately does not say whether the address exists; the UI
      // must not invent a more specific message than the one it was given.
      setError('Email or password is incorrect.');
      return { mfaRequired: false as const, failed: true };
    } finally {
      setPending(false);
    }
  };

  const submitCode = async (code: string) => {
    if (!challenge) return { ok: false };
    setPending(true);
    setError(null);
    try {
      setSession(await verifyMfa(challenge.pending_token, code));
      setChallenge(null);
      return { ok: true };
    } catch {
      setError('That code is not valid. Codes expire after 30 seconds.');
      return { ok: false };
    } finally {
      setPending(false);
    }
  };

  return { submitPassword, submitCode, challenge, error, pending };
}

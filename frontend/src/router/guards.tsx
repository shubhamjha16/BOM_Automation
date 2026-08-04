import type { ReactNode } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { CAN_APPROVE, type Role } from '@/shared/constants/roles';
import { useSessionStore } from '@/features/auth';
import { ROUTES } from '@/shared/constants/routes';

/**
 * Route guards hide what a user cannot use. **They are not access control.**
 *
 * Every guard here is a rendering decision made from a token the browser holds,
 * and a browser is not a trustworthy place to make security decisions. The
 * server enforces tenancy in the repository layer and roles in
 * `services/access/authz.py`, and it does so whether or not these guards ran.
 * Removing them would make the console confusing; it would not make it insecure.
 */

export function RequireAuth({ children }: { children: ReactNode }) {
  const token = useSessionStore((state) => state.accessToken);
  const location = useLocation();

  if (!token) {
    return <Navigate to={ROUTES.signin} state={{ from: location }} replace />;
  }
  return <>{children}</>;
}

export function RequireRole({
  allow,
  children,
}: {
  allow: readonly Role[];
  children: ReactNode;
}) {
  const role = useSessionStore((state) => state.role);

  if (!role) return <Navigate to={ROUTES.signin} replace />;
  if (!allow.includes(role)) return <Navigate to={ROUTES.dashboard} replace />;
  return <>{children}</>;
}

/** Manager or above. Self-approval is refused server-side regardless. */
export function RequireApprover({ children }: { children: ReactNode }) {
  return <RequireRole allow={CAN_APPROVE}>{children}</RequireRole>;
}

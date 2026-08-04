/**
 * Frontend env is public by definition — it ships in the bundle. Nothing secret
 * belongs here, and the check below is about failing at boot rather than at the
 * first request.
 */

const required = (name: string, value: string | undefined): string => {
  if (!value) {
    throw new Error(
      `${name} is not set. Copy frontend/.env.example to .env.local and fill it in.`,
    );
  }
  return value;
};

export const env = {
  apiBaseUrl: required('VITE_API_BASE_URL', import.meta.env.VITE_API_BASE_URL),
  sentryDsn: import.meta.env.VITE_SENTRY_DSN ?? '',
} as const;

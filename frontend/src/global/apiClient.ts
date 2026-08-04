import { env } from './env';
import { ApiError } from './errors';

/**
 * The single HTTP entry point. Callers pass a type drawn from
 * `global/apiTypes.ts`, which re-exports the generated OpenAPI types — a
 * backend schema change that is not regenerated fails CI, so these are never
 * hand-maintained guesses about the wire format.
 */
async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(`${env.apiBaseUrl}${path}`, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...init.headers },
    credentials: 'include',
  });

  if (!response.ok) {
    let detail: unknown;
    try {
      detail = await response.json();
    } catch {
      detail = await response.text();
    }
    throw new ApiError(response.status, `${init.method ?? 'GET'} ${path} failed`, detail);
  }

  return response.status === 204 ? (undefined as T) : ((await response.json()) as T);
}

export const apiClient = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: 'POST', body: JSON.stringify(body ?? {}) }),
  patch: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: 'PATCH', body: JSON.stringify(body ?? {}) }),
};

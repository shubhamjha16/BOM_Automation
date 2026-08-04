/** A typed API error, so the console can distinguish refusals from failures. */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly detail?: unknown,
  ) {
    super(message);
    this.name = 'ApiError';
  }

  /**
   * Tenancy returns 404 rather than 403 so existence does not leak (S5). The
   * console must therefore treat a 404 as "not found", never as "no access" —
   * saying "you lack permission" would leak exactly what the 404 protects.
   */
  get isNotFound(): boolean {
    return this.status === 404;
  }

  /** An exhausted quota is a real UI state, never a 500 (S21). */
  get isQuotaExceeded(): boolean {
    return this.status === 429;
  }
}

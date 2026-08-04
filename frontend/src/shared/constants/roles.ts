export const ROLES = ['partner', 'manager', 'assessor', 'readonly', 'client'] as const;
export type Role = (typeof ROLES)[number];

/**
 * An assessment cannot be issued on one person's judgement: the assessor who ran
 * it cannot approve it, and approval requires manager or above (S13). Enforced
 * server-side; this is only what the console reveals.
 */
export const CAN_APPROVE: readonly Role[] = ['partner', 'manager'];

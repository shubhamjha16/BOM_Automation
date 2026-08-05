/**
 * Re-export of the generated OpenAPI types.
 *
 * `packages/api-types/index.d.ts` is generated from the backend schema by
 * `make api-types`, and CI fails if it is stale — so a backend shape change
 * cannot reach the console as a runtime surprise. Nothing here is hand-written;
 * edit the backend schema and regenerate.
 */

import type { components, paths } from '@bom-automation/api-types';

export type { components, paths };

export type Schema<K extends keyof components['schemas']> = components['schemas'][K];

export type SubmissionOut = Schema<'SubmissionOut'>;
export type SubmissionDetailOut = Schema<'SubmissionDetailOut'>;
export type SubmissionCreate = Schema<'SubmissionCreate'>;
export type DocumentIn = Schema<'DocumentIn'>;
export type DocumentOut = Schema<'DocumentOut'>;
export type LaneRollupOut = Schema<'LaneRollupOut'>;
export type JobOut = Schema<'JobOut'>;
export type JobDetailOut = Schema<'JobDetailOut'>;
export type NodeRunOut = Schema<'NodeRunOut'>;

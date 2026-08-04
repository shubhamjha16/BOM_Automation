import { describe, expect, it } from 'vitest';
import { compareClauses, formatClause, parseClause } from '@/utils/clause';
import { formatScore } from '@/utils/format';
import {
  FIELD_VERDICT_PRESENTATION,
  LANE_VERDICT_PRESENTATION,
} from '@/shared/constants/verdicts';

describe('clause parsing', () => {
  it('parses a section with an ordinal', () => {
    expect(parseClause('4.2(5)')).toEqual({ section: '4.2', ordinal: 5 });
  });

  it('parses a section without one', () => {
    expect(parseClause('8.5.1')).toEqual({ section: '8.5.1', ordinal: null });
  });

  it('returns null rather than guessing', () => {
    expect(parseClause('roughly clause five')).toBeNull();
    expect(parseClause('')).toBeNull();
  });

  it('formats for display', () => {
    expect(formatClause('4.2(21)')).toBe('s.4.2(21)');
    expect(formatClause('9.3')).toBe('s.9.3');
  });

  it('sorts in document order, not lexically', () => {
    const sorted = ['4.2(10)', '4.2(2)', '4.2(1)', '10.2(1)'].sort(compareClauses);
    expect(sorted).toEqual(['4.2(1)', '4.2(2)', '4.2(10)', '10.2(1)']);
  });
});

describe('score formatting', () => {
  it('renders a null score as an em dash, never as zero', () => {
    expect(formatScore(null)).toBe('—');
    expect(formatScore(undefined)).toBe('—');
  });

  it('renders a real score', () => {
    expect(formatScore(85)).toBe('85.0%');
    expect(formatScore(0)).toBe('0.0%');
  });
});

describe('verdict presentation', () => {
  it('distinguishes lane_not_applicable from lane_absent', () => {
    expect(LANE_VERDICT_PRESENTATION.lane_not_applicable.isFinding).toBe(false);
    expect(LANE_VERDICT_PRESENTATION.lane_absent.isFinding).toBe(true);
    expect(LANE_VERDICT_PRESENTATION.lane_not_applicable.tone).not.toBe(
      LANE_VERDICT_PRESENTATION.lane_absent.tone,
    );
  });

  it('never presents not_determinable as a pass or as a supplier defect', () => {
    const nd = FIELD_VERDICT_PRESENTATION.not_determinable;
    expect(nd.tone).toBe('neutral');
    expect(nd.countsAgainstSupplier).toBe(false);
    expect(nd.label).not.toMatch(/present|compliant|pass/i);
  });
});

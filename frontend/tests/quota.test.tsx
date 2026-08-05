/**
 * S21: an exhausted quota is a real UI state, never a 500.
 *
 * Asserted on the rendered screen rather than on the hook, because the exit
 * condition is about what a client sees. A 429 the console turns into "Could not
 * load submissions" would satisfy every backend test here and still report a
 * healthy service as broken.
 */
import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import {
  QuotaExceededState,
  QuotaMeter,
  consumedFraction,
  isExhausted,
  isNearLimit,
  isQuotaRefusal,
  resetSentence,
  type QuotaRefusal,
  type QuotaRow,
} from '@/features/quota';
import { ApiError } from '@/global/errors';

const refusal: QuotaRefusal = {
  detail: 'submissions_per_month limit of 25 reached on the starter plan (25 used).',
  quota: 'submissions_per_month',
  limit: 25,
  used: 25,
  plan: 'starter',
  resets_at: '2026-09-01T00:00:00+00:00',
  retry_after_seconds: 2_332_800,
  remedy: 'The allowance resets at the start of next month.',
};

function row(overrides: Partial<QuotaRow> = {}): QuotaRow {
  return {
    quota: 'submissions_per_month',
    limit: 25,
    used: 5,
    remaining: 20,
    unlimited: false,
    ...overrides,
  };
}

describe('recognising a refusal', () => {
  it('reads a 429 as a quota state', () => {
    const error = new ApiError(429, 'POST /submissions failed', refusal);
    expect(error.isQuotaExceeded).toBe(true);
    expect(isQuotaRefusal(error.detail)).toBe(true);
  });

  it('does not read a 500 as one', () => {
    expect(new ApiError(500, 'boom', { detail: 'internal' }).isQuotaExceeded).toBe(false);
  });

  it('recognises the body structurally rather than by its prose', () => {
    const reworded = { ...refusal, detail: 'entirely different wording', remedy: 'do this' };
    expect(isQuotaRefusal(reworded)).toBe(true);
  });

  it('rejects a partial body rather than rendering undefined at a client', () => {
    expect(isQuotaRefusal({ quota: 'submissions_per_month' })).toBe(false);
    expect(isQuotaRefusal(null)).toBe(false);
    expect(isQuotaRefusal('429 Too Many Requests')).toBe(false);
  });
});

describe('the exhausted-quota screen', () => {
  it('names the quota, the limit and the usage', () => {
    render(<QuotaExceededState refusal={refusal} />);

    expect(screen.getByText(/Submissions this month — limit reached/)).toBeTruthy();
    // Used and limit are both 25 here, deliberately: the screen has to state
    // both rather than collapsing "you are at your limit" into one number.
    expect(screen.getAllByText('25', { selector: 'strong' })).toHaveLength(2);
    expect(screen.getByText('starter')).toBeTruthy();
  });

  it("shows the server's own remedy rather than console-invented advice", () => {
    render(<QuotaExceededState refusal={refusal} />);
    expect(screen.getByText(refusal.remedy)).toBeTruthy();
  });

  it('is a status rather than an alert', () => {
    /* The request was valid and the service is healthy. Announcing it as an
       error trains clients to read a billing limit as an outage. */
    render(<QuotaExceededState refusal={refusal} />);
    expect(screen.getByRole('status')).toBeTruthy();
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('says what remains reachable', () => {
    render(<QuotaExceededState refusal={refusal} />);
    expect(screen.getByText(/already completed remain available/)).toBeTruthy();
  });

  it('does not offer a retry for a quota that never resets', () => {
    /* The component limit is refused, not deferred. "Try again later" would send
       a client back in a month with the same 50,000-component document. */
    render(
      <QuotaExceededState
        refusal={{
          ...refusal,
          quota: 'components_per_submission',
          resets_at: null,
          retry_after_seconds: 0,
          remedy: 'Split the submission or change plan.',
        }}
      />,
    );
    expect(screen.getByText(/Waiting will not lift this one/)).toBeTruthy();
  });

  it('renders an unmapped quota key rather than a blank heading', () => {
    render(<QuotaExceededState refusal={{ ...refusal, quota: 'some_future_quota' }} />);
    expect(screen.getByText(/some_future_quota — limit reached/)).toBeTruthy();
  });
});

describe('reset wording', () => {
  it('counts hours when the reset is close', () => {
    const sentence = resetSentence(
      { ...refusal, resets_at: '2026-08-06T00:00:00+00:00' },
      new Date('2026-08-05T00:00:00Z'),
    );
    expect(sentence).toBe('The allowance resets in about 24 hours.');
  });

  it('gives a date when it is further out', () => {
    const sentence = resetSentence(refusal, new Date('2026-08-05T00:00:00Z'));
    expect(sentence).toMatch(/resets on /);
  });

  it('returns null when nothing resets', () => {
    expect(resetSentence({ ...refusal, resets_at: null })).toBeNull();
  });
});

describe('the meter, before a limit is reached', () => {
  it('warns from 80% and not before', () => {
    expect(isNearLimit(row({ used: 19 }))).toBe(false);
    expect(isNearLimit(row({ used: 20 }))).toBe(true);
    expect(isNearLimit(row({ used: 25 }))).toBe(false);
    expect(isExhausted(row({ used: 25 }))).toBe(true);
  });

  it('treats unlimited as no fraction rather than as zero', () => {
    /* A bar at zero reads as *no allowance*, which is the opposite of what an
       unlimited quota means. */
    expect(consumedFraction(row({ unlimited: true, limit: null }))).toBeNull();
    expect(isNearLimit(row({ unlimited: true, limit: null }))).toBe(false);
  });

  it('renders "no limit" for an unlimited quota, with no progress bar', () => {
    render(<QuotaMeter row={row({ unlimited: true, limit: null, remaining: null })} />);
    expect(screen.getByText('No limit on this plan')).toBeTruthy();
    expect(screen.queryByRole('progressbar')).toBeNull();
  });

  it('caps the fill at 100% when a plan change puts usage over the limit', () => {
    expect(consumedFraction(row({ used: 40 }))).toBe(1);
  });

  it('exposes the allowance to a screen reader', () => {
    render(<QuotaMeter row={row({ used: 20 })} />);
    const bar = screen.getByRole('progressbar');
    expect(bar.getAttribute('aria-valuenow')).toBe('20');
    expect(bar.getAttribute('aria-valuemax')).toBe('25');
  });

  it('carries a tone the stylesheet can key on', () => {
    const { container } = render(<QuotaMeter row={row({ used: 25 })} />);
    expect(container.querySelector('[data-tone="fail"]')).toBeTruthy();
  });
});

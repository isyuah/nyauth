import { describe, expect, it } from 'vitest';
import { turnstilePresentation } from './turnstile';

describe('turnstilePresentation', () => {
  it('lets Managed widgets appear only when Cloudflare requires interaction', () => {
    expect(turnstilePresentation('managed')).toEqual({
      appearance: 'interaction-only',
      reserveSpace: false,
      showProgress: false,
    });
  });

  it('keeps Non-interactive verification visible while it runs', () => {
    expect(turnstilePresentation('non-interactive')).toEqual({
      appearance: 'always',
      reserveSpace: true,
      showProgress: true,
    });
  });

  it('gives Invisible verification no visible footprint', () => {
    expect(turnstilePresentation('invisible')).toEqual({
      appearance: 'execute',
      reserveSpace: false,
      showProgress: false,
    });
  });
});

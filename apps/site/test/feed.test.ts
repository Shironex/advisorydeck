import type { Advisory } from '@advisorydeck/contract';
import { describe, expect, it } from 'vitest';
import { kevState } from '../src/lib/feed.ts';

function withKev(kev: Advisory['kev']): Advisory {
  return { kev } as Advisory;
}

describe('kevState', () => {
  it('listed: in KEV, with the date it was added', () => {
    expect(kevState(withKev({ listed: true, added_at: '2026-11-01', checked: true }))).toEqual({
      state: 'listed',
      addedAt: '2026-11-01',
    });
  });

  it('checked and not listed: not in KEV', () => {
    expect(kevState(withKev({ listed: false, added_at: null, checked: true }))).toEqual({
      state: 'not-listed',
    });
  });

  it('checked false or missing: not checked, never "not listed"', () => {
    expect(kevState(withKev({ listed: false, added_at: null, checked: false }))).toEqual({
      state: 'not-checked',
    });
    expect(kevState(withKev({ listed: false, added_at: null }))).toEqual({ state: 'not-checked' });
  });
});

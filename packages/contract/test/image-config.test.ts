import { describe, expect, it } from 'vitest';
import { durationSeconds, imageConfigProblems, type ImageConfig } from '../src/index.ts';

const base: ImageConfig = {
  version: 1,
  feed: { url: 'https://feed.example.org/api/v1/' },
  products: [{ slug: 'postgresql', version: '17' }],
  channels: [{ type: 'discord', url_env: 'DISCORD_WEBHOOK_URL' }],
};

describe('image config rules', () => {
  it('parses durations', () => {
    expect(durationSeconds('30m')).toBe(1800);
    expect(durationSeconds('2h')).toBe(7200);
    expect(durationSeconds('90s')).toBe(90);
    expect(durationSeconds('1d')).toBeUndefined();
  });

  it('accepts the defaults', () => {
    expect(imageConfigProblems(base)).toEqual([]);
  });

  it('rejects a poll interval under 5m', () => {
    expect(imageConfigProblems({ ...base, feed: { ...base.feed, poll_interval: '299s' } })).toEqual(
      ['feed.poll_interval must be at least 5m'],
    );
  });

  it('rejects a product listed twice and an unknown time zone', () => {
    const config: ImageConfig = {
      ...base,
      products: [base.products[0], { slug: 'postgresql', version: '16' }],
      digest: { timezone: 'Mars/Olympus_Mons' },
    };
    expect(imageConfigProblems(config)).toHaveLength(2);
  });
});

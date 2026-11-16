/** The product page version check against the committed feed, with the matcher's rules. */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { repoRoot } from '@advisorydeck/contract';
import { describe, expect, it } from 'vitest';
import { checkInstalled, type CheckFeed } from '../src/lib/verdict.ts';

const feed = (slug: string): CheckFeed =>
  JSON.parse(
    readFileSync(join(repoRoot(), 'data/api/v1/products', `${slug}.json`), 'utf8'),
  ) as CheckFeed;

describe('checkInstalled against the committed PostgreSQL feed', () => {
  const pg = feed('postgresql');
  const latest17 = pg.product.branches.find((b) => b.name === '17')?.latest ?? '';

  it('an old release is affected and the latest release of its branch fixes everything', () => {
    const verdict = checkInstalled(pg, '17.0');
    expect(verdict.kind).toBe('affected');
    if (verdict.kind !== 'affected') return;
    expect(verdict.branch?.name).toBe('17');
    expect(verdict.advice).toMatchObject({ kind: 'latest', version: latest17 });
    expect(verdict.affected.length).toBeGreaterThan(0);
    const total = Object.values(verdict.counts).reduce((a, b) => a + b, 0);
    expect(total).toBe(verdict.affected.length);
  });

  it('the latest release of a supported branch is clear', () => {
    expect(checkInstalled(pg, latest17)).toMatchObject({ kind: 'clear' });
  });

  it('a branch (floating tag) is affected, as the matcher answers for branches', () => {
    expect(checkInstalled(pg, '17')).toMatchObject({ kind: 'affected', isBranch: true });
  });

  it('text that is not a PostgreSQL version is invalid, never clear', () => {
    expect(checkInstalled(pg, 'latest')).toMatchObject({ kind: 'invalid' });
    expect(checkInstalled(pg, '17.4.1')).toMatchObject({ kind: 'invalid' });
  });
});

describe('checkInstalled for a floating tag deeper than its branch', () => {
  it('Node.js: the 22.23 tag belongs to the endoflife.date branch 22', () => {
    expect(checkInstalled(feed('nodejs'), '22.23')).toMatchObject({ branch: { name: '22' } });
  });
});

describe('checkInstalled for a product without branch data', () => {
  it('Coolify: an old beta is affected and gets the highest listed fix', () => {
    const verdict = checkInstalled(feed('coolify'), '4.0.0-beta.300');
    expect(verdict.kind).toBe('affected');
    if (verdict.kind !== 'affected') return;
    expect(verdict.branch).toBeNull();
    expect(verdict.advice.kind).toBe('upgrade');
  });

  it('unknown ranges keep a version from reading as clear', () => {
    expect(checkInstalled(feed('coolify'), '99.0.0').kind).not.toBe('clear');
  });
});

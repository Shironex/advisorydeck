import type { CatalogEntry, Product } from '@advisorydeck/contract';
import { describe, expect, it } from 'vitest';
import { ANONYMOUS_MAX_PAGES, ghsaQueries, planGhsaRequests } from '../src/ghsa.ts';

function entry(slug: string, sources: Product['sources']): CatalogEntry {
  const product = {
    slug,
    name: slug,
    homepage: 'https://example.com',
    category: 'proxies',
    description: slug,
    version_scheme: 'semver',
    branches: { source: 'none' },
    images: [],
    sources,
    match: { strategy: 'package-ranges' },
    curated: false,
  } satisfies Product;
  return { file: `catalog/proxies/${slug}.yml`, product };
}

const entries = [
  entry('a', [
    { type: 'ghsa-repo', repo: 'owner/a' },
    { type: 'ghsa-package', ecosystem: 'go', package: 'example.com/a/v2' },
  ]),
  entry('b', [
    { type: 'ghsa-package', ecosystem: 'go', package: 'example.com/b' },
    { type: 'ghsa-package', ecosystem: 'npm', package: '@scope/b' },
  ]),
];

describe('ghsa queries', () => {
  it('asks once per repository and once per ecosystem for every package', () => {
    const queries = ghsaQueries(entries);
    expect(queries.map((q) => q.key)).toEqual(['global:go', 'global:npm', 'repo:owner/a']);
    const go = queries[0];
    expect(go?.url).toContain('ecosystem=go&affects=example.com%2Fa%2Fv2,example.com%2Fb&');
    expect(go?.cursorKeys).toEqual(['package:go:example.com/a/v2', 'package:go:example.com/b']);
    expect(queries[1]?.url).toContain('affects=%40scope%2Fb&');
  });

  it('splits a long package list so every URL stays short', () => {
    const many = Array.from({ length: 250 }, (_, i) =>
      entry(`p${String(i)}`, [
        { type: 'ghsa-package', ecosystem: 'npm', package: `package-${String(i)}` },
      ]),
    );
    const queries = ghsaQueries(many);
    expect(queries.length).toBeGreaterThan(2);
    expect(queries.every((q) => q.cursorKeys.length <= 100 && q.url.length <= 2000)).toBe(true);
    expect(queries.flatMap((q) => q.cursorKeys)).toHaveLength(250);
  });

  it('plans the worst case from the stored cursors', () => {
    const queries = ghsaQueries(entries);
    const fresh = planGhsaRequests(queries, { ghsa: {} }, false);
    expect(fresh).toEqual({ minimum: 3, worstCase: 3 * ANONYMOUS_MAX_PAGES, withoutCursor: 3 });
    // A batch with one package lacking a cursor reads its whole history again.
    const state = {
      ghsa: {
        'repo:owner/a': '2026-11-01T00:00:00Z',
        'package:go:example.com/a/v2': '2026-11-01T00:00:00Z',
        'package:npm:@scope/b': '2026-11-01T00:00:00Z',
      },
    };
    expect(planGhsaRequests(queries, state, false)).toEqual({
      minimum: 3,
      worstCase: 2 + ANONYMOUS_MAX_PAGES,
      withoutCursor: 1,
    });
  });
});

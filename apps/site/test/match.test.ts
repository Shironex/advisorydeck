/**
 * The browser matcher runs the same vectors as the Go matcher in image/internal/match:
 * fixtures/match/versions.json for parsing and ordering, fixtures/match/advisories/*.json for
 * real advisories with their expected outcome, reason and fix.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { repoRoot } from '@advisorydeck/contract';
import { describe, expect, it } from 'vitest';
import {
  check,
  compareVersions,
  inBranch,
  isBranch,
  parseVersion,
  tryParse,
  type MatchRange,
  type Scheme,
} from '../src/lib/match.ts';

const repo = repoRoot();
// The caller names the shape of the fixture it reads.
// eslint-disable-next-line @typescript-eslint/no-unnecessary-type-parameters
const read = <T>(rel: string): T => JSON.parse(readFileSync(join(repo, rel), 'utf8')) as T;

interface VersionVectors {
  compare: { scheme: Scheme; a: string; b: string; want: number }[];
  branch: { scheme: Scheme; version: string; branch: boolean }[];
  invalid: { scheme: Scheme; version: string }[];
}

interface AdvisoryVectors {
  product: string;
  scheme: Scheme;
  advisories: {
    id: string;
    ranges: MatchRange[];
    cases: { version: string; outcome: string; reason: string; fixed?: string }[];
  }[];
}

const versions = read<VersionVectors>('fixtures/match/versions.json');
const vectorFiles = readdirSync(join(repo, 'fixtures/match/advisories')).filter((f) =>
  f.endsWith('.json'),
);

describe('version vectors (fixtures/match/versions.json)', () => {
  it.each(versions.compare)('$scheme: compare($a, $b) = $want', ({ scheme, a, b, want }) => {
    const va = parseVersion(scheme, a);
    const vb = parseVersion(scheme, b);
    expect(compareVersions(va, vb)).toBe(want);
    expect(compareVersions(vb, va)).toBe(-want || 0);
  });

  it.each(versions.branch)('$scheme: $version is a branch: $branch', (c) => {
    expect(isBranch(parseVersion(c.scheme, c.version))).toBe(c.branch);
  });

  it.each(versions.invalid)('$scheme: "$version" does not parse', ({ scheme, version }) => {
    expect(tryParse(scheme, version)).toBeNull();
  });
});

describe('advisory vectors (fixtures/match/advisories)', () => {
  it('has one vector file per catalog product', () => {
    expect(vectorFiles.length).toBeGreaterThanOrEqual(5);
  });

  for (const file of vectorFiles) {
    const vec = read<AdvisoryVectors>(`fixtures/match/advisories/${file}`);
    const cases = vec.advisories.flatMap((advisory) =>
      advisory.cases.map((c) => ({ ...c, id: advisory.id, ranges: advisory.ranges })),
    );
    it.each(cases)(`${vec.product} $id at $version: $outcome ($reason)`, (c) => {
      const got = check(vec.scheme, c.version, vec.product, {
        id: c.id,
        affected: [{ product: vec.product, ranges: c.ranges }],
      });
      expect({ outcome: got.outcome, reason: got.reason, fixed: got.fixedIn }).toEqual({
        outcome: c.outcome,
        reason: c.reason,
        fixed: c.fixed ?? '',
      });
      expect(got.detail).not.toBe('');
      if (got.outcome === 'affected') {
        expect(got.range).not.toBeNull();
      }
    });
  }
});

describe('the published PostgreSQL feed fixture', () => {
  const feed = read<{
    product: {
      slug: string;
      version_scheme: Scheme;
      branches: { name: string; latest: string | null }[];
    };
    advisories: { id: string; affected: { product: string; ranges: MatchRange[] }[] }[];
  }>('fixtures/api/v1/products/postgresql.json');
  const [advisory] = feed.advisories;

  it('every branch is affected, and its latest release is not', () => {
    if (advisory === undefined) throw new Error('no advisory in the fixture');
    for (const branch of feed.product.branches) {
      const onBranch = check(feed.product.version_scheme, branch.name, 'postgresql', advisory);
      expect(onBranch.outcome, branch.name).toBe('affected');
      expect(onBranch.branch).toBe(true);
      if (branch.latest !== null) {
        expect(
          check(feed.product.version_scheme, branch.latest, 'postgresql', advisory).outcome,
          branch.latest,
        ).toBe('not-affected');
      }
    }
  });
});

describe('inBranch', () => {
  it('places releases in their branch and nothing else', () => {
    const v = (s: string): ReturnType<typeof parseVersion> => parseVersion('pg', s);
    expect(inBranch(v('17.4'), v('17'))).toBe(true);
    expect(inBranch(v('18.0'), v('17'))).toBe(false);
    expect(inBranch(v('9.6.24'), v('9.6'))).toBe(true);
    const s = (x: string): ReturnType<typeof parseVersion> => parseVersion('semver', x);
    expect(inBranch(s('3.7.18'), s('3.7'))).toBe(true);
    expect(inBranch(s('2.11.62'), s('3.7'))).toBe(false);
    expect(inBranch(s('3.7.18'), s('3.7.18'))).toBe(false);
  });
});

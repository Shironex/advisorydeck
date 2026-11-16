import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  loadCatalog,
  repoRoot,
  type CatalogEntry,
  type Product,
  type VersionRange,
} from '@advisorydeck/contract';
import { describe, expect, it } from 'vitest';
import { pickRanges } from '../src/advisories.ts';
import { cveFacts, ghsaFacts, type Catalogue, type RecordFacts } from '../src/normalize.ts';
import { trimCve, trimGhsa, type GhsaRecord } from '../src/records.ts';
import { buildSourceIndex } from '../src/source-index.ts';

// Record shapes of products the catalog does not hold yet, from real records fetched on
// 2026-11-16 (test/fixtures/README.md). The products below exist only in this test.

const here = join(repoRoot(), 'packages/ingest/test/fixtures');

function product(
  slug: string,
  sources: Product['sources'],
  scheme: Product['version_scheme'] = 'semver',
): CatalogEntry {
  return {
    file: `test/${slug}.yml`,
    product: {
      slug,
      name: slug,
      category: 'paas',
      homepage: 'https://example.com',
      version_scheme: scheme,
      branches: { source: 'none' },
      images: [],
      sources,
      match: { strategy: 'vendor-ranges' },
      curated: false,
    },
  };
}

const extra: CatalogEntry[] = [
  product('n8n', [{ type: 'ghsa-repo', repo: 'n8n-io/n8n' }]),
  product('authentik', [
    { type: 'ghsa-repo', repo: 'goauthentik/authentik' },
    { type: 'cve-cna', assigner: 'GitHub_M', vendor: 'goauthentik', products: ['authentik'] },
  ]),
  product('keycloak', [{ type: 'ghsa-repo', repo: 'keycloak/keycloak' }]),
  product('php', [
    { type: 'ghsa-repo', repo: 'php/php-src' },
    { type: 'cve-cna', assigner: 'php', vendor: 'PHP Group', products: ['PHP'] },
  ]),
  product('mysql', [{ type: 'cve-cna', assigner: 'oracle', products: ['MySQL Server'] }]),
  product('mariadb', [
    { type: 'ghsa-repo', repo: 'MariaDB/server' },
    { type: 'cve-cna', assigner: 'GitHub_M', vendor: 'MariaDB', products: ['server'] },
  ]),
  product('rocket-chat', [
    { type: 'cve-cna', assigner: 'hackerone', vendor: 'Rocket.Chat', products: ['Rocket.Chat'] },
  ]),
];

const entries = [...loadCatalog().entries, ...extra];
const built = buildSourceIndex(entries);
const catalogue: Catalogue = { entries, index: built.index };

// eslint-disable-next-line @typescript-eslint/no-unnecessary-type-parameters -- typed fixture reader
function json<T>(path: string): T {
  return JSON.parse(readFileSync(path, 'utf8')) as T;
}

function cve(id: string): RecordFacts {
  const record = trimCve(json(join(here, 'cve', `${id}.json`)));
  if (record === undefined) throw new Error(id);
  return cveFacts(record, catalogue);
}

function repoGhsa(file: string, id: string, repository: string): RecordFacts {
  const raw = json<Record<string, unknown>[]>(join(here, 'ghsa', file)).find(
    (a) => a['ghsa_id'] === id,
  );
  if (raw === undefined) throw new Error(id);
  const record: GhsaRecord = { id, repository, repo: trimGhsa(raw), global: null };
  return ghsaFacts(record, catalogue);
}

function rangesOf(facts: RecordFacts, slug: string): VersionRange[] {
  return pickRanges(facts.claims).find((a) => a.product === slug)?.ranges ?? [];
}

/** Ranges the matcher fixtures (fixtures/match) expect for one advisory. */
function matcherRanges(slug: string, id: string): VersionRange[] {
  const file = json<{ advisories: { id: string; ranges: VersionRange[] }[] }>(
    join(repoRoot(), 'fixtures/match/advisories', `${slug}.json`),
  );
  const advisory = file.advisories.find((a) => a.id === id);
  if (advisory === undefined) throw new Error(`${id} not in fixtures/match`);
  return advisory.ranges;
}

it('the test catalogue has no clashing sources', () => {
  expect(built.issues).toEqual([]);
});

describe('one upper bound per branch on separate entries (G1)', () => {
  it('n8n: four entries become one range per branch, so a patched 2.48.3 is not affected', () => {
    const facts = repoGhsa('repo-n8n.json', 'GHSA-c772-hjfp-gfc2', 'n8n-io/n8n');
    expect(rangesOf(facts, 'n8n')).toEqual(matcherRanges('n8n', 'GHSA-c772-hjfp-gfc2'));
    expect(facts.warnings.join('\n')).toContain('one range per branch');
  });

  it('Keycloak: an unlisted line between two listed ones stays affected', () => {
    const facts = repoGhsa('repo-keycloak.json', 'GHSA-95cx-vmr5-3cmr', 'keycloak/keycloak');
    expect(rangesOf(facts, 'keycloak')).toEqual(matcherRanges('keycloak', 'GHSA-95cx-vmr5-3cmr'));
  });

  it('authentik: last affected versions with their patches, one per branch', () => {
    const facts = repoGhsa('repo-authentik.json', 'GHSA-cxwx-9x59-28qm', 'goauthentik/authentik');
    expect(rangesOf(facts, 'authentik')).toEqual(matcherRanges('authentik', 'GHSA-cxwx-9x59-28qm'));
  });

  it('authentik: the bounded CVE record is read as written', () => {
    expect(rangesOf(cve('CVE-2026-94613'), 'authentik')).toEqual([
      { introduced: '0', fixed: '2026.2.7' },
      { introduced: '2026.5.0', fixed: '2026.5.7' },
      { introduced: '2026.8.0', fixed: '2026.8.2' },
    ]);
  });

  it('PHP: one entry per supported branch', () => {
    const facts = repoGhsa('repo-php-src.json', 'GHSA-w8hw-w9fx-j79w', 'php/php-src');
    expect(rangesOf(facts, 'php')).toEqual(matcherRanges('php', 'GHSA-w8hw-w9fx-j79w'));
  });

  it('Rocket.Chat: CVE versions all from 0, and a fix that is the first release of its line', () => {
    expect(rangesOf(cve('CVE-2026-65645'), 'rocket-chat')).toEqual([
      { introduced: '0', fixed: '7.10.15' },
      { introduced: '8.0.0', fixed: '8.1.8' },
      { introduced: '8.2.0', fixed: '8.2.8' },
      { introduced: '8.3.0', fixed: '8.3.8' },
      { introduced: '8.4.0', fixed: '8.4.6' },
      { introduced: '8.5.0', fixed: '8.5.3' },
      { introduced: '8.6.0', fixed: '8.6.2' },
      { introduced: '8.7.0', fixed: '8.7.1' },
      // "< 8.8.0" next to "< 8.7.1": only the 8.8.0 prereleases are left for it.
      { introduced: '8.8.0-0', fixed: '8.8.0' },
    ]);
  });
});

describe('hyphen ranges without spaces (G2)', () => {
  it('MySQL: 8.4.0-8.4.12 is a range, so 8.4.5 is affected', () => {
    expect(rangesOf(cve('CVE-2026-101801'), 'mysql')).toEqual(
      matcherRanges('mysql', 'CVE-2026-101801'),
    );
  });

  it('MariaDB: hyphen ranges and a lone version next to a patched list', () => {
    const facts = repoGhsa('repo-mariadb.json', 'GHSA-m5gf-432r-g5jw', 'MariaDB/server');
    expect(rangesOf(facts, 'mariadb')).toEqual(matcherRanges('mariadb', 'GHSA-m5gf-432r-g5jw'));
  });

  it('MariaDB: the CVE record with ordinary bounds is unchanged', () => {
    expect(rangesOf(cve('CVE-2026-102523'), 'mariadb')).toEqual([
      { introduced: '10.11.1', fixed: '10.11.19' },
      { introduced: '11.4.1', fixed: '11.4.13' },
      { introduced: '11.8.1', fixed: '11.8.9' },
      { introduced: '12.3.1', fixed: '12.3.3' },
      { introduced: '13.0.1', fixed: '13.0.2' },
    ]);
  });
});

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
import { buildAdvisory, clusterRecords, pickRanges } from '../src/advisories.ts';
import {
  cveFacts,
  cveRanges,
  ghsaFacts,
  ghsaRanges,
  type Catalogue,
  type RecordFacts,
} from '../src/normalize.ts';
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
  product('n8n', [
    { type: 'ghsa-repo', repo: 'n8n-io/n8n' },
    // VulnCheck writes the vendor both as n8n and as n8n-io.
    { type: 'cve-cna', assigner: 'VulnCheck', products: ['n8n'] },
  ]),
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
  product('nextcloud', [
    { type: 'ghsa-repo', repo: 'nextcloud/security-advisories', packages: ['Server'] },
  ]),
  product('tomcat', [{ type: 'cve-cna', assigner: 'apache', products: ['Apache Tomcat'] }]),
  product('spring-web', [
    { type: 'ghsa-package', ecosystem: 'maven', package: 'org.springframework:spring-web' },
  ]),
  product('python', [{ type: 'cve-cna', assigner: 'PSF', products: ['CPython'] }]),
  product('django', [{ type: 'ghsa-package', ecosystem: 'pip', package: 'django' }]),
  product('nodejs', [
    { type: 'cve-cna', assigner: 'hackerone', vendor: 'nodejs', products: ['node'] },
  ]),
  product('nginx', [{ type: 'cve-cna', assigner: 'f5', products: ['NGINX Open Source'] }]),
  product('go', [
    { type: 'cve-cna', assigner: 'Go', vendor: 'Go standard library', products: ['*'] },
  ]),
  product('metabase', [{ type: 'ghsa-repo', repo: 'metabase/metabase' }]),
  product('valkey', [
    { type: 'ghsa-repo', repo: 'valkey-io/valkey' },
    { type: 'cve-cna', assigner: 'GitHub_M', vendor: 'valkey-io', products: ['valkey'] },
  ]),
  product('mattermost', [{ type: 'cve-cna', assigner: 'Mattermost', products: ['Mattermost'] }]),
  product('jenkins', [{ type: 'cve-cna', assigner: 'jenkins', products: ['Jenkins'] }]),
  product('portainer', [{ type: 'ghsa-repo', repo: 'portainer/portainer' }]),
  product('runc', [{ type: 'ghsa-repo', repo: 'opencontainers/runc' }]),
  product('rocket-chat', [
    { type: 'cve-cna', assigner: 'hackerone', vendor: 'Rocket.Chat', products: ['Rocket.Chat'] },
  ]),
];

// A product added to the catalog later keeps its test entry out, so the two never clash.
const catalogEntries = loadCatalog().entries;
const inCatalog = new Set(catalogEntries.map((e) => e.product.slug));
const entries = [...catalogEntries, ...extra.filter((e) => !inCatalog.has(e.product.slug))];
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

function globalGhsa(file: string, id: string): RecordFacts {
  const raw = json<Record<string, unknown>[]>(join(here, 'ghsa', file)).find(
    (a) => a['ghsa_id'] === id,
  );
  if (raw === undefined) throw new Error(id);
  return ghsaFacts({ id, repository: null, repo: null, global: trimGhsa(raw) }, catalogue);
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

describe('a lower and an upper bound joined by a space', () => {
  it('n8n: one entry lists three ranges, the middle two without commas', () => {
    const facts = repoGhsa('repo-n8n.json', 'GHSA-jh8h-6c9q-7gmw', 'n8n-io/n8n');
    expect(rangesOf(facts, 'n8n')).toEqual([
      { introduced: '0', fixed: '1.123.22' },
      { introduced: '2.0.0', fixed: '2.9.3' },
      { introduced: '2.10.0', fixed: '2.10.1' },
    ]);
  });
});

describe('lower bounds with a patched list (G3)', () => {
  it('Nextcloud: three lower bounds pair with three patched versions', () => {
    const facts = repoGhsa(
      'repo-nextcloud.json',
      'GHSA-f99w-3pm7-v4cv',
      'nextcloud/security-advisories',
    );
    expect(rangesOf(facts, 'nextcloud')).toEqual(matcherRanges('nextcloud', 'GHSA-f99w-3pm7-v4cv'));
  });

  it('lower bounds that do not pair with the patched list are unknown, not affected forever', () => {
    // GHSA-5j59-xgg2-r9c4 (vercel/next.js) as published: four lower bounds, ten patches.
    const reading = ghsaRanges({
      package: { ecosystem: 'npm', name: 'next' },
      vulnerable_version_range: '>= 13.3, >= 14, >=15, >=16',
      patched_versions:
        '13.5.11, 14.2.35, 15.0.7, 15.1.11, 15.2.8, 15.3.8, 15.4.10, 15.5.9, 16.0.10, 16.1.1',
    });
    expect(reading.ranges).toBeUndefined();
    expect(reading.note).toContain('do not pair');
  });

  it('lower bounds with no patch yet stay open', () => {
    expect(
      ghsaRanges({
        package: { ecosystem: 'nextcloud', name: 'Server' },
        vulnerable_version_range: '>= 32.0.0, >= 33.0.0',
        patched_versions: 'TBD',
      }).ranges,
    ).toEqual([{ introduced: '32.0.0' }, { introduced: '33.0.0' }]);
  });
});

describe('a ghsa-repo source that names its packages (G3)', () => {
  const advisory = (id: string, packages?: [string, ...string[]]) => {
    const raw = json<Record<string, unknown>[]>(join(here, 'ghsa/repo-nextcloud.json')).find(
      (a) => a['ghsa_id'] === id,
    );
    if (raw === undefined) throw new Error(id);
    const entry = product('nextcloud', [
      {
        type: 'ghsa-repo',
        repo: 'nextcloud/security-advisories',
        ...(packages === undefined ? {} : { packages }),
      },
    ]);
    const only: Catalogue = { entries: [entry], index: buildSourceIndex([entry]).index };
    const record: GhsaRecord = {
      id,
      repository: 'nextcloud/security-advisories',
      repo: trimGhsa(raw),
      global: null,
    };
    return ghsaFacts(record, only);
  };

  it('Nextcloud: only the named entries count, compared without case', () => {
    // Server under both ecosystems (nextcloud and nextcloud enterprise), not the files_lock app.
    expect(rangesOf(advisory('GHSA-22w9-gpgv-pcgc', ['server']), 'nextcloud')).toEqual([
      { introduced: '34.0.0', fixed: '34.0.1' },
      { introduced: '32.0.0', fixed: '32.0.6' },
      { introduced: '33.0.0', fixed: '33.0.6' },
    ]);
    expect(rangesOf(advisory('GHSA-22w9-gpgv-pcgc', ['files_lock']), 'nextcloud')).toEqual([
      { introduced: '32.0.0', fixed: '32.0.6' },
      { introduced: '33.0.0', fixed: '33.0.6' },
    ]);
  });

  it('an advisory naming none of the packages is not about the product', () => {
    expect(advisory('GHSA-22w9-gpgv-pcgc', ['Richdocuments']).claims).toEqual([]);
  });
});

describe('a CVE record linked to the GHSA it references (G4)', () => {
  function cluster(records: RecordFacts[]) {
    const clusters = clusterRecords(records);
    const facts = new Map(records.map((r) => [r.id, r]));
    return { clusters, advisories: clusters.map((ids) => buildAdvisory(ids, facts, new Map())) };
  }

  it('n8n: a VulnCheck CVE and the repository advisory without a CVE id are one advisory', () => {
    const vulncheck = cve('CVE-2026-126384');
    expect(vulncheck.links).toEqual(['GHSA-f2cw-9483-7vcp']);
    const ghsa = repoGhsa('repo-n8n.json', 'GHSA-f2cw-9483-7vcp', 'n8n-io/n8n');
    expect(ghsa.links).toEqual([]);
    const { clusters, advisories } = cluster([vulncheck, ghsa]);
    expect(clusters).toEqual([['CVE-2026-126384', 'GHSA-f2cw-9483-7vcp']]);
    expect(advisories).toHaveLength(1);
    expect(advisories[0]?.id).toBe('CVE-2026-126384');
    expect(advisories[0]?.aliases).toEqual(['GHSA-f2cw-9483-7vcp']);
    // The repository advisory is the more trusted source in this catalogue, read per branch.
    expect(advisories[0]?.affected).toEqual([
      {
        product: 'n8n',
        ranges: [
          { introduced: '0', fixed: '1.123.89' },
          { introduced: '2.0.0', fixed: '2.45.5' },
          { introduced: '2.46.0', fixed: '2.46.1' },
          { introduced: '3.0.0', fixed: '3.0.1' },
        ],
      },
    ]);
  });

  it('n8n: the second VulnCheck shape (one affected entry, vendor n8n) links the same way', () => {
    const vulncheck = cve('CVE-2026-56353');
    expect(vulncheck.links).toEqual(['GHSA-jh8h-6c9q-7gmw']);
    expect(rangesOf(vulncheck, 'n8n')).toEqual([
      { introduced: '0', fixed: '1.123.22' },
      { introduced: '2.0.0', fixed: '2.9.3' },
      { introduced: '2.10.0', fixed: '2.10.1' },
    ]);
    const { clusters } = cluster([
      vulncheck,
      repoGhsa('repo-n8n.json', 'GHSA-jh8h-6c9q-7gmw', 'n8n-io/n8n'),
    ]);
    expect(clusters).toEqual([['CVE-2026-56353', 'GHSA-jh8h-6c9q-7gmw']]);
  });

  it('a second CVE filed for a GHSA that already names one joins the same advisory', () => {
    // The GHSA as it reads once GitHub assigns its own CVE id (constructed from the real record).
    const raw = json<Record<string, unknown>[]>(join(here, 'ghsa/repo-n8n.json')).find(
      (a) => a['ghsa_id'] === 'GHSA-f2cw-9483-7vcp',
    );
    const named = trimGhsa({ ...raw, cve_id: 'CVE-2026-999001' });
    const ghsa = ghsaFacts(
      { id: named.ghsa_id, repository: 'n8n-io/n8n', repo: named, global: null },
      catalogue,
    );
    const { clusters, advisories } = cluster([cve('CVE-2026-126384'), ghsa]);
    expect(clusters).toEqual([['CVE-2026-126384', 'CVE-2026-999001', 'GHSA-f2cw-9483-7vcp']]);
    expect(advisories[0]?.aliases).toEqual(['CVE-2026-999001', 'GHSA-f2cw-9483-7vcp']);
  });

  it('a CVE record citing several GHSAs links none of them', () => {
    const record = trimCve(json(join(here, 'cve/CVE-2026-126384.json')));
    if (record === undefined) throw new Error('CVE-2026-126384');
    record.containers.cna.references = [
      ...(record.containers.cna.references ?? []),
      { url: 'https://github.com/advisories/GHSA-2x68-96jw-5x8c' },
    ];
    const facts = cveFacts(record, catalogue);
    expect(facts.links).toEqual([]);
    expect(facts.warnings.join('\n')).toContain('several GitHub advisories');
  });

  it('records without a GHSA reference keep no link', () => {
    expect(cve('CVE-2026-101801').links).toEqual([]);
  });
});

describe('smaller normalisations', () => {
  it('Tomcat: a dotted milestone (9.0.0.M1) is a prerelease', () => {
    expect(rangesOf(cve('CVE-2026-74049'), 'tomcat')).toEqual(
      matcherRanges('tomcat', 'CVE-2026-74049'),
    );
  });

  it('Python: PEP 440 prereleases in a CVE record become semver prereleases', () => {
    expect(rangesOf(cve('CVE-2026-12345'), 'python')).toEqual(
      matcherRanges('python', 'CVE-2026-12345'),
    );
  });

  it('Django: PEP 440 lower bounds in a pip advisory become semver prereleases', () => {
    expect(rangesOf(globalGhsa('global-django.json', 'GHSA-q238-5cxm-5c9h'), 'django')).toEqual(
      matcherRanges('django', 'GHSA-q238-5cxm-5c9h'),
    );
  });

  it('Node.js: lines that start at their last affected release are read as up to it', () => {
    const facts = cve('CVE-2026-106072');
    expect(rangesOf(facts, 'nodejs')).toEqual(matcherRanges('nodejs', 'CVE-2026-106072'));
    expect(facts.warnings.join('\n')).toContain('read as every version up to it');
  });

  it('a single line that starts at its last affected release stays one version', () => {
    const record = trimCve(json(join(here, 'cve/CVE-2026-106072.json')));
    const affected = record?.containers.cna.affected?.[0];
    if (record === undefined || affected === undefined) throw new Error('CVE-2026-106072');
    affected.versions = (affected.versions ?? []).slice(0, 1);
    expect(rangesOf(cveFacts(record, catalogue), 'nodejs')).toEqual([
      { introduced: '22.23.3', last_affected: '22.23.3' },
    ]);
  });

  it('nginx: an open range ends where the next listed line starts', () => {
    const facts = cve('CVE-2026-95101');
    expect(rangesOf(facts, 'nginx')).toEqual(matcherRanges('nginx', 'CVE-2026-95101'));
    expect(facts.warnings.join('\n')).toContain('ends before the next listed line starts');
  });

  it('Go: a vendor-wide rule takes every package the record names', () => {
    const facts = cve('CVE-2026-56866');
    expect(facts.claims.map((c) => c.slug)).toEqual(['go']);
    expect(rangesOf(facts, 'go')).toEqual(matcherRanges('go', 'CVE-2026-56866'));
  });

  it('Metabase: an x. placeholder major is read as 0. (open source) and 1. (Enterprise)', () => {
    const facts = repoGhsa('repo-metabase.json', 'GHSA-r495-55cx-fjh7', 'metabase/metabase');
    expect(rangesOf(facts, 'metabase')).toEqual(matcherRanges('metabase', 'GHSA-r495-55cx-fjh7'));
    expect(facts.warnings.join('\n')).toContain('read as 0. (open source) and 1. (Enterprise)');
  });

  it('Spring: .RELEASE is the release itself', () => {
    expect(
      rangesOf(globalGhsa('global-spring-web.json', 'GHSA-ccgv-vj62-xf9h'), 'spring-web'),
    ).toEqual([
      { introduced: '6.1.0', fixed: '6.1.4' },
      { introduced: '6.0.0', fixed: '6.0.17' },
      { introduced: '5.3.0', fixed: '5.3.32' },
      { introduced: '0', last_affected: '5.2.25' },
    ]);
  });

  it('PHP: a wildcard line (8.2.*) starts at its first release', () => {
    expect(rangesOf(cve('CVE-2026-109618'), 'php')).toEqual(
      matcherRanges('php', 'CVE-2026-109618'),
    );
  });
});

describe('upper bounds of one expression in any order', () => {
  it('Valkey: newest first, sorted so the newest bound does not cover the older branches', () => {
    const facts = repoGhsa('repo-valkey.json', 'GHSA-jcj7-v34w-v9vv', 'valkey-io/valkey');
    expect(rangesOf(facts, 'valkey')).toEqual(matcherRanges('valkey', 'GHSA-jcj7-v34w-v9vv'));
  });

  it('Valkey: one upper bound next to a patched list is read per patched branch', () => {
    const facts = repoGhsa('repo-valkey.json', 'GHSA-c677-q3wr-gggq', 'valkey-io/valkey');
    expect(rangesOf(facts, 'valkey')).toEqual(matcherRanges('valkey', 'CVE-2026-21863'));
    expect(facts.warnings.join('\n')).toContain('read as one range per patched branch');
  });

  it('a patched list that does not close the upper bound leaves the range as written', () => {
    expect(
      ghsaRanges({
        package: { ecosystem: '', name: 'valkey-server' },
        vulnerable_version_range: '<= 9.0.2',
        patched_versions: '9.1.0, 8.1.6',
      }).ranges,
    ).toEqual([{ introduced: '0', last_affected: '9.0.2' }]);
  });
});

describe('unaffected versions inside the affected ranges', () => {
  it('Mattermost: patched branches listed as unaffected are cut out of ranges from 0', () => {
    const facts = cve('CVE-2026-16049');
    expect(rangesOf(facts, 'mattermost')).toEqual(matcherRanges('mattermost', 'CVE-2026-16049'));
    expect(facts.warnings.join('\n')).toContain('were subtracted');
  });

  it('Mattermost: an unaffected desktop or mobile build that cannot be ordered makes it unknown', () => {
    const facts = cve('CVE-2026-22880');
    expect(facts.claims).toEqual([expect.objectContaining({ slug: 'mattermost', ranges: [] })]);
    expect(facts.warnings.join('\n')).toContain('cannot be subtracted');
  });

  it('Jenkins: only unaffected versions under a default status of affected', () => {
    const facts = cve('CVE-2025-67638');
    expect(rangesOf(facts, 'jenkins')).toEqual(matcherRanges('jenkins', 'CVE-2025-67638'));
    expect(facts.warnings.join('\n')).toContain('read as every other version');
  });

  it('unaffected versions after the ranges change nothing', () => {
    expect(
      cveRanges({
        product: 'Mattermost',
        defaultStatus: 'unaffected',
        versions: [
          { version: '11.7.0', lessThanOrEqual: '11.7.6', status: 'affected' },
          { version: '10.11.0', lessThanOrEqual: '10.11.21', status: 'affected' },
          { version: '11.9.0', status: 'unaffected' },
          { version: '11.7.7', status: 'unaffected' },
          { version: '10.11.22', status: 'unaffected' },
        ],
      }),
    ).toEqual([
      { introduced: '11.7.0', last_affected: '11.7.6' },
      { introduced: '10.11.0', last_affected: '10.11.21' },
    ]);
  });
});

describe('an open GHSA range next to a later bounded line', () => {
  it('Portainer: the LTS line without a fix ends where the next line starts', () => {
    const facts = repoGhsa('repo-portainer.json', 'GHSA-jmr9-98g4-2phv', 'portainer/portainer');
    expect(rangesOf(facts, 'portainer')).toEqual(matcherRanges('portainer', 'GHSA-jmr9-98g4-2phv'));
    expect(facts.warnings.join('\n')).toContain('ends before the next listed line starts');
  });

  it('Portainer: a closed range with no patched version stays closed', () => {
    const facts = repoGhsa('repo-portainer.json', 'GHSA-j3mf-q9qf-5qf8', 'portainer/portainer');
    expect(rangesOf(facts, 'portainer')).toEqual(matcherRanges('portainer', 'GHSA-j3mf-q9qf-5qf8'));
  });
});

describe('a prerelease upper bound of a branch', () => {
  it('runc: <= 1.5.0-rc.2 starts at the lowest 1.5.0 prerelease, not at 1.5.0', () => {
    const facts = repoGhsa('repo-runc.json', 'GHSA-xjvp-4fhw-gc47', 'opencontainers/runc');
    expect(rangesOf(facts, 'runc')).toEqual(matcherRanges('runc', 'CVE-2026-41579'));
  });
});

describe('operators written after the version or joined by &&', () => {
  it('Ghost: v3.23.0>= is a lower bound', () => {
    const facts = repoGhsa('repo-ghost.json', 'GHSA-q98w-jm4q-wch7', 'TryGhost/Ghost');
    expect(rangesOf(facts, 'ghost')).toEqual(matcherRanges('ghost', 'GHSA-q98w-jm4q-wch7'));
  });

  it('Ghost: >= 6.19.4 && < 6.21.1 is one range', () => {
    const facts = repoGhsa('repo-ghost.json', 'GHSA-g366-23fw-ggp6', 'TryGhost/Ghost');
    expect(rangesOf(facts, 'ghost')).toEqual([{ introduced: '6.19.4', fixed: '6.21.1' }]);
  });
});

describe('a patched version equal to an inclusive upper bound', () => {
  it('Ghost: <= 6.50.0 patched in 6.50.0 reads 6.50.0 as fixed, with a note', () => {
    const facts = repoGhsa('repo-ghost.json', 'GHSA-mp9q-4q6m-44f5', 'TryGhost/Ghost');
    expect(rangesOf(facts, 'ghost')).toEqual(matcherRanges('ghost', 'CVE-2026-103292'));
    expect(facts.warnings.join('\n')).toContain('read the patch as the fix');
  });
});

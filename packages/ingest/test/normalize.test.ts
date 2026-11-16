import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { loadCatalog, repoRoot, type Advisory, type VersionRange } from '@advisorydeck/contract';
import { describe, expect, it } from 'vitest';
import { buildAdvisory, clusterRecords, pickRanges } from '../src/advisories.ts';
import {
  cveFacts,
  ghsaFacts,
  ghsaRanges,
  type Catalogue,
  type RecordFacts,
} from '../src/normalize.ts';
import { trimCve, trimGhsa, trimKev, type GhsaRecord } from '../src/records.ts';
import { buildSourceIndex } from '../src/source-index.ts';

const here = join(repoRoot(), 'packages/ingest/test/fixtures');
const catalog = loadCatalog();
const catalogue: Catalogue = {
  entries: catalog.entries,
  index: buildSourceIndex(catalog.entries).index,
};

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
function matcherRanges(product: string, id: string): VersionRange[] {
  const file = json<{ advisories: { id: string; ranges: VersionRange[] }[] }>(
    join(repoRoot(), 'fixtures/match/advisories', `${product}.json`),
  );
  const advisory = file.advisories.find((a) => a.id === id);
  if (advisory === undefined) throw new Error(`${id} not in fixtures/match`);
  return advisory.ranges;
}

describe('CVE records', () => {
  it('builds the hand-made fixture advisory from the real PostgreSQL record', () => {
    const facts = cve('CVE-2026-120154');
    // Enrichment as recorded on 2026-11-16: the KEV catalog (not listed) and the EPSS score.
    const advisory = buildAdvisory(['CVE-2026-120154'], new Map([[facts.id, facts]]), new Map(), {
      kev: trimKev(json(join(here, 'kev/known_exploited_vulnerabilities.json'))),
      epss: {
        scores: { 'CVE-2026-120154': { score: 0.00295, percentile: 0.22351, date: '2026-11-15' } },
      },
      nvd: new Map(),
    });
    const fixture = json<Advisory>(
      join(repoRoot(), 'fixtures/data/advisories/CVE-2026-120154.json'),
    );
    expect(advisory).toEqual({ ...fixture, revision: advisory?.revision, note: null });
    expect(advisory?.note).toBeNull();
    expect(advisory?.revision).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it('reads a range written inside the version field (Redis, GitHub_M)', () => {
    expect(rangesOf(cve('CVE-2026-25243'), 'redis')).toEqual(
      matcherRanges('redis', 'CVE-2026-25243'),
    );
  });

  it('keeps no product for a record outside the catalog', () => {
    expect(cve('CVE-2025-71466').claims).toEqual([]);
    expect(cve('CVE-2026-59734').claims).toEqual([]);
  });
});

describe('GHSA repository advisories, against the matcher fixtures', () => {
  it('Traefik: v2 module starts at 2.0.0, patched versions become fixed', () => {
    const facts = repoGhsa('repo-traefik.json', 'GHSA-p956-6gvv-mxqp', 'traefik/traefik');
    expect(rangesOf(facts, 'traefik')).toEqual(matcherRanges('traefik', 'GHSA-p956-6gvv-mxqp'));
    expect(facts.links).toEqual([]);
  });

  it('Coolify: the patched version later than the range wins, with a data-quality note', () => {
    const facts = repoGhsa('repo-coolify-2.json', 'GHSA-qfcc-2fm3-9q42', 'coollabsio/coolify');
    expect(rangesOf(facts, 'coolify')).toEqual([{ introduced: '0', fixed: '4.0.0-beta.471' }]);
    expect(facts.warnings.join('\n')).toContain('kept the stricter reading');
    expect(facts.links).toEqual(['CVE-2026-34592']);
  });

  it('Coolify: a junk package name is noted and the range is still read', () => {
    const facts = repoGhsa('repo-coolify-2.json', 'GHSA-9pp4-wcmj-rq73', 'coollabsio/coolify');
    expect(rangesOf(facts, 'coolify')).toEqual([{ introduced: '0', fixed: '4.0.0-beta.470' }]);
    expect(facts.warnings.join('\n')).toContain('malformed package name');
  });

  it('Coolify: a trailing space in the range is trimmed', () => {
    const facts = repoGhsa('repo-coolify-2.json', 'GHSA-5cg9-38qj-8mc3', 'coollabsio/coolify');
    expect(rangesOf(facts, 'coolify')).toEqual([{ introduced: '0', fixed: '4.0.0-beta.420.7' }]);
  });

  it('Coolify: a bare version contradicting its patch is published as unknown', () => {
    const facts = repoGhsa('repo-coolify-1.json', 'GHSA-j6j2-frv3-g6f7', 'coollabsio/coolify');
    expect(facts.claims).toEqual([expect.objectContaining({ slug: 'coolify', ranges: [] })]);
  });

  it('moby: only the Docker Engine entry maps to Docker Engine versions', () => {
    const facts = repoGhsa('repo-moby.json', 'GHSA-6jhp-7446-hf7f', 'moby/moby');
    expect(rangesOf(facts, 'docker-engine')).toEqual(
      matcherRanges('docker-engine', 'CVE-2026-115538'),
    );
  });

  it('Redis: All with one patched version per branch becomes per-branch ranges', () => {
    const facts = repoGhsa('repo-redis.json', 'GHSA-4789-qfc9-5f9q', 'redis/redis');
    expect(rangesOf(facts, 'redis')).toEqual(matcherRanges('redis', 'GHSA-4789-qfc9-5f9q'));
  });

  it('Redis: All and TBD carry no range', () => {
    const facts = repoGhsa('repo-redis.json', 'GHSA-c8h9-259x-jff4', 'redis/redis');
    expect(rangesOf(facts, 'redis')).toEqual(matcherRanges('redis', 'GHSA-c8h9-259x-jff4'));
  });

  it('docker-ce: a list of last affected versions is one range per branch', () => {
    const { ranges } = ghsaRanges({
      package: { ecosystem: 'docker-ce', name: 'docker-ce' },
      vulnerable_version_range:
        '<= v19.03.15, <= v20.10.27, <= v23.0.14, <= v24.0.9, <= v25.0.5, <= v26.0.2, <= v26.1.4, <= v27.0.3, <= v27.1.0',
      patched_versions: '> v23.0.14, > v26.1.4, > v27.1.0',
    });
    expect(ranges).toEqual(matcherRanges('docker-engine', 'CVE-2024-41110'));
  });
});

describe('clustering', () => {
  it('joins a GHSA and its CVE under the CVE id, and the CVE range fills a GHSA without one', () => {
    const records = [
      cve('CVE-2026-25243'),
      repoGhsa('repo-redis.json', 'GHSA-c8h9-259x-jff4', 'redis/redis'),
    ];
    const clusters = clusterRecords(records);
    expect(clusters).toEqual([['CVE-2026-25243', 'GHSA-c8h9-259x-jff4']]);
    const facts = new Map(records.map((r) => [r.id, r]));
    const advisory = buildAdvisory(clusters[0] ?? [], facts, new Map());
    expect(advisory?.id).toBe('CVE-2026-25243');
    expect(advisory?.aliases).toEqual(['GHSA-c8h9-259x-jff4']);
    expect(advisory?.affected).toEqual([
      { product: 'redis', ranges: [{ introduced: '0', fixed: '8.6.3' }] },
    ]);
    expect(advisory?.severity.source).toBe('cna');
    expect(advisory?.sources.map((s) => `${s.type} ${s.license}`)).toEqual([
      'cve-cna CVE-TOU',
      'ghsa CC-BY-4.0',
    ]);
  });

  it('uses the GHSA id when there is no CVE', () => {
    const facts = repoGhsa('repo-traefik.json', 'GHSA-x5pf-cqh3-2gv8', 'traefik/traefik');
    const advisory = buildAdvisory([facts.id], new Map([[facts.id, facts]]), new Map());
    expect(advisory?.id).toBe('GHSA-x5pf-cqh3-2gv8');
    expect(advisory?.aliases).toEqual([]);
  });
});

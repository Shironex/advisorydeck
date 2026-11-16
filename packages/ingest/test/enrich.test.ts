import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { loadCatalog, repoRoot, type Advisory } from '@advisorydeck/contract';
import { describe, expect, it } from 'vitest';
import { buildAdvisory, revisionOf } from '../src/advisories.ts';
import {
  epssBatches,
  epssMoved,
  fetchEpss,
  fetchKev,
  KEV_URLS,
  kevOf,
  mergeEpss,
  nvdDue,
  nvdSeverity,
  type Enrichment,
} from '../src/enrich.ts';
import { Http } from '../src/http.ts';
import { cveFacts, type Catalogue, type RecordFacts } from '../src/normalize.ts';
import { trimCve, trimKev, trimNvd, type KevCatalog } from '../src/records.ts';
import { buildSourceIndex } from '../src/source-index.ts';

const here = join(repoRoot(), 'packages/ingest/test/fixtures');
const catalog = loadCatalog();
const catalogue: Catalogue = {
  entries: catalog.entries,
  index: buildSourceIndex(catalog.entries).index,
};

function read(path: string): unknown {
  return JSON.parse(readFileSync(join(here, path), 'utf8')) as unknown;
}

function cve(id: string): RecordFacts {
  const record = trimCve(read(`cve/${id}.json`));
  if (record === undefined) throw new Error(id);
  return cveFacts(record, catalogue);
}

const recordedKev = trimKev(read('kev/known_exploited_vulnerabilities.json'));

function serve(table: Record<string, string>): Http {
  return new Http({
    fetch: (url) =>
      Promise.resolve(
        table[url] === undefined
          ? new Response('not found', { status: 404 })
          : new Response(table[url], { status: 200 }),
      ),
    sleep: () => Promise.resolve(),
  });
}

describe('CISA KEV', () => {
  it('keeps every CVE id with its date from the recorded feed', () => {
    expect(recordedKev?.catalog_version).toBe('2026.11.13');
    expect(recordedKev?.entries['CVE-2022-0543']).toBe('2022-03-28');
    expect(Object.keys(recordedKev?.entries ?? {})).toHaveLength(4);
    expect(trimKev({ hello: 'world' })).toBeUndefined();
  });

  it('falls back to the mirror when cisa.gov fails', async () => {
    const body = readFileSync(join(here, 'kev/known_exploited_vulnerabilities.json'), 'utf8');
    const kev = await fetchKev(serve({ [KEV_URLS[1]]: body }));
    expect(kev.catalog_version).toBe('2026.11.13');
    await expect(fetchKev(serve({}))).rejects.toThrow('no KEV catalog');
  });

  it('says not checked without a catalog, and checked when the catalog was read', () => {
    expect(kevOf(['CVE-2026-120154'], undefined)).toEqual({
      listed: false,
      added_at: null,
      checked: false,
    });
    expect(kevOf(['CVE-2026-120154'], recordedKev)).toEqual({
      listed: false,
      added_at: null,
      checked: true,
    });
    expect(kevOf(['CVE-2019-15752', 'CVE-2022-0543'], recordedKev)).toEqual({
      listed: true,
      added_at: '2021-11-03',
      checked: true,
    });
  });

  it('marks a listed advisory, attributes KEV and changes the revision', () => {
    const facts = cve('CVE-2026-120154');
    const plain = buildAdvisory([facts.id], new Map([[facts.id, facts]]), new Map(), {
      kev: recordedKev,
      epss: { scores: {} },
      nvd: new Map(),
    });
    // A synthetic catalog that lists this CVE (no real KEV entry exists for it).
    const listedCatalog: KevCatalog = {
      catalog_version: 'test',
      date_released: '2026-11-16T00:00:00Z',
      entries: { 'CVE-2026-120154': '2026-11-16' },
    };
    const listed = buildAdvisory([facts.id], new Map([[facts.id, facts]]), new Map(), {
      kev: listedCatalog,
      epss: { scores: {} },
      nvd: new Map(),
    });
    expect(listed?.kev).toEqual({ listed: true, added_at: '2026-11-16', checked: true });
    expect(listed?.sources.map((s) => s.type)).toEqual(['cve-cna', 'kev']);
    expect(listed?.revision).not.toBe(plain?.revision);
  });
});

describe('EPSS', () => {
  it('reads the recorded API answer', async () => {
    const url = 'https://api.first.org/data/v1/epss?cve=CVE-2026-120154,CVE-2026-25243&limit=100';
    const answer = JSON.stringify({
      ...(read('epss/feed-cves.json') as object),
    });
    const scores = await fetchEpss(serve({ [url]: answer }), ['CVE-2026-120154', 'CVE-2026-25243']);
    expect(scores.get('CVE-2026-120154')).toEqual({
      score: 0.00295,
      percentile: 0.22351,
      date: '2026-11-15',
    });
  });

  it('splits CVE ids under the API limits (2000 characters, 100 rows)', () => {
    const ids = Array.from({ length: 250 }, (_, i) => `CVE-2026-${String(100000 + i)}`);
    const batches = epssBatches(ids);
    expect(batches.flat()).toEqual(ids);
    for (const batch of batches) {
      expect(batch.length).toBeLessThanOrEqual(100);
      expect(batch.join(',').length).toBeLessThan(2000);
    }
  });

  it('republishes a score only when it moves materially', () => {
    const old = { score: 0.003, percentile: 0.5, date: '2026-11-14' };
    expect(epssMoved(old, { score: 0.0031, percentile: 0.503, date: '2026-11-15' })).toBe(false);
    expect(epssMoved(old, { score: 0.003, percentile: 0.52, date: '2026-11-15' })).toBe(true);
    expect(epssMoved(old, { score: 0.0045, percentile: 0.505, date: '2026-11-15' })).toBe(true);
    const near = { score: 0.08, percentile: 0.945, date: '2026-11-14' };
    expect(epssMoved(near, { score: 0.081, percentile: 0.951, date: '2026-11-15' })).toBe(true);
    const merged = mergeEpss(
      { scores: { 'CVE-1': old, 'CVE-GONE': old } },
      new Map([['CVE-1', { score: 0.0031, percentile: 0.503, date: '2026-11-15' }]]),
      new Set(['CVE-1']),
    );
    expect(merged).toEqual({ scores: { 'CVE-1': old } });
  });
});

describe('severity chain', () => {
  const nvd = trimNvd(read('nvd/CVE-2026-25243.json'), 'CVE-2026-25243', '2026-11-16');

  it("prefers NVD's own score from the recorded record", () => {
    expect(nvdSeverity(nvd)).toEqual({
      level: 'high',
      score: 8.8,
      vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
      source: 'nvd',
    });
  });

  it('uses NVD only when neither the CNA nor GitHub scored the CVE', () => {
    const facts = cve('CVE-2026-25243');
    const enrichment: Enrichment = {
      kev: recordedKev,
      epss: { scores: {} },
      nvd: new Map([['CVE-2026-25243', nvd ?? { id: '', fetched_at: '', metrics: [] }]]),
    };
    const scored = buildAdvisory([facts.id], new Map([[facts.id, facts]]), new Map(), enrichment);
    expect(scored?.severity.source).toBe('cna');
    const unscored: RecordFacts = { ...facts, severity: undefined };
    const fallback = buildAdvisory(
      [facts.id],
      new Map([[facts.id, unscored]]),
      new Map(),
      enrichment,
    );
    expect(fallback?.severity).toMatchObject({ level: 'high', score: 8.8, source: 'nvd' });
    expect(fallback?.sources.map((s) => s.type)).toEqual(['cve-cna', 'nvd']);
    const none = buildAdvisory([facts.id], new Map([[facts.id, unscored]]), new Map(), {
      ...enrichment,
      nvd: new Map(),
    });
    expect(none?.severity).toEqual({ level: 'unknown', score: null, vector: null, source: 'none' });
  });

  it('asks NVD again for a record without metrics after a week', () => {
    const empty = { id: 'CVE-1', fetched_at: '2026-11-10', metrics: [] };
    expect(nvdDue(undefined, '2026-11-16')).toBe(true);
    expect(nvdDue(empty, '2026-11-16')).toBe(false);
    expect(nvdDue(empty, '2026-11-17')).toBe(true);
    expect(nvdDue(nvd, '2027-01-01')).toBe(false);
  });
});

describe('material revision', () => {
  const facts = cve('CVE-2026-120154');
  const base = buildAdvisory([facts.id], new Map([[facts.id, facts]]), new Map(), {
    kev: recordedKev,
    epss: { scores: { [facts.id]: { score: 0.003, percentile: 0.22, date: '2026-11-15' } } },
    nvd: new Map(),
  });
  if (base === undefined) throw new Error('no advisory');
  const revise = (change: (a: Advisory) => void): string => {
    const copy = structuredClone(base);
    change(copy);
    return revisionOf(copy);
  };

  it('ignores trivial upstream edits', () => {
    expect(revise((a) => (a.summary = `${a.summary} Edited.`))).toBe(base.revision);
    expect(revise((a) => (a.title = 'A new title'))).toBe(base.revision);
    expect(revise((a) => (a.modified_at = '2026-11-20T00:00:00.000Z'))).toBe(base.revision);
    expect(revise((a) => a.references.push({ url: 'https://example.org/x', type: 'web' }))).toBe(
      base.revision,
    );
    expect(revise((a) => (a.severity.score = 4.9))).toBe(base.revision);
    expect(revise((a) => (a.epss = { score: 0.004, percentile: 0.3, date: '2026-11-16' }))).toBe(
      base.revision,
    );
    expect(revise((a) => (a.kev = { listed: false, added_at: null }))).toBe(base.revision);
    // Filling a score for the first time (null before enrichment existed) is not material either.
    expect(revise((a) => (a.epss = null))).toBe(base.revision);
  });

  it('changes on a material change', () => {
    expect(revise((a) => (a.severity.level = 'high'))).not.toBe(base.revision);
    expect(
      revise((a) => (a.kev = { listed: true, added_at: '2026-11-16', checked: true })),
    ).not.toBe(base.revision);
    expect(revise((a) => (a.epss = { score: 0.2, percentile: 0.97, date: '2026-11-16' }))).not.toBe(
      base.revision,
    );
    expect(revise((a) => a.affected[0].ranges.push({ introduced: '19', fixed: '19.1' }))).not.toBe(
      base.revision,
    );
  });
});

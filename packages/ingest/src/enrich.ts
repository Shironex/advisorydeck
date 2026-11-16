import type { Advisory } from '@advisorydeck/contract';
import type { Http } from './http.ts';
import type { Severity, SourceRef } from './normalize.ts';
import { levelFromScore } from './normalize.ts';
import {
  trimKev,
  trimNvd,
  type EpssScore,
  type EpssScores,
  type KevCatalog,
  type NvdRecord,
} from './records.ts';

/**
 * Enrichment: exploitation signals and the last step of the severity chain.
 *
 * - CISA KEV (CC0-1.0): the JSON feed on cisa.gov, with the cisagov/kev-data mirror as a
 *   fallback. The whole catalog of CVE ids is kept, so offline runs can still check every CVE.
 * - EPSS (FIRST, free, attribution requested): the api.first.org lookup API, in batches, only for
 *   the CVEs of the feed and at most once a day.
 * - NVD API 2.0: CVSS for CVEs that neither the CNA nor GitHub scored, a few per run, six seconds
 *   apart as NIST asks for clients without an API key.
 */

export const KEV_URLS = [
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
  'https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json',
] as const;
export const EPSS_API = 'https://api.first.org/data/v1/epss';
export const NVD_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

/** EPSS percentile from which an advisory counts as likely exploited (revision and image bypass). */
export const EPSS_SIGNAL_PERCENTILE = 0.95;
/** The API takes at most 2000 characters in the cve parameter and returns 100 rows a page. */
const EPSS_BATCH_CHARS = 1900;
const EPSS_BATCH_IDS = 100;
/** Hours between EPSS refreshes: scores change once a day. */
export const EPSS_REFRESH_HOURS = 20;

export const NVD_SPACING_MS = 6000;
export const NVD_MAX_PER_RUN = 20;
/** Days before a stored NVD record without metrics is asked again. */
export const NVD_RETRY_DAYS = 7;

/** What advisory building reads from the enrichment sources. */
export interface Enrichment {
  /** Undefined when the KEV catalog was never read: every advisory is then "not checked". */
  kev: KevCatalog | undefined;
  epss: EpssScores;
  nvd: ReadonlyMap<string, NvdRecord>;
}

export const noEnrichment: Enrichment = { kev: undefined, epss: { scores: {} }, nvd: new Map() };

/** Reads the KEV catalog from the first URL that answers with a valid feed. */
export async function fetchKev(http: Http): Promise<KevCatalog> {
  const problems: string[] = [];
  for (const url of KEV_URLS) {
    try {
      const response = await http.json<unknown>(url);
      const catalog = response === undefined ? undefined : trimKev(response.data);
      if (catalog !== undefined) return catalog;
      problems.push(`${url}: ${response === undefined ? 'not found' : 'not a KEV feed'}`);
    } catch (error) {
      problems.push(String(error));
    }
  }
  throw new Error(`no KEV catalog: ${problems.join('; ')}`);
}

/** CVE ids in batches that fit the EPSS API's cve parameter. */
export function epssBatches(ids: readonly string[]): string[][] {
  const batches: string[][] = [];
  let current: string[] = [];
  let chars = 0;
  for (const id of ids) {
    if (
      current.length > 0 &&
      (chars + id.length + 1 > EPSS_BATCH_CHARS || current.length >= EPSS_BATCH_IDS)
    ) {
      batches.push(current);
      current = [];
      chars = 0;
    }
    current.push(id);
    chars += id.length + 1;
  }
  if (current.length > 0) batches.push(current);
  return batches;
}

interface EpssRow {
  cve?: unknown;
  epss?: unknown;
  percentile?: unknown;
  date?: unknown;
}

function unit(value: unknown): number | undefined {
  const n = typeof value === 'string' ? Number(value) : value;
  return typeof n === 'number' && Number.isFinite(n) && n >= 0 && n <= 1 ? n : undefined;
}

/** Looks up EPSS scores; CVEs EPSS has not scored yet are simply missing from the result. */
export async function fetchEpss(
  http: Http,
  ids: readonly string[],
): Promise<Map<string, EpssScore>> {
  const out = new Map<string, EpssScore>();
  for (const batch of epssBatches(ids)) {
    const url = `${EPSS_API}?cve=${batch.join(',')}&limit=${EPSS_BATCH_IDS}`;
    const response = await http.json<{ data?: EpssRow[] }>(url);
    for (const row of response?.data.data ?? []) {
      const score = unit(row.epss);
      const percentile = unit(row.percentile);
      if (
        typeof row.cve !== 'string' ||
        score === undefined ||
        percentile === undefined ||
        typeof row.date !== 'string' ||
        !/^\d{4}-\d{2}-\d{2}$/.test(row.date)
      ) {
        continue;
      }
      out.set(row.cve, { score, percentile, date: row.date });
    }
  }
  return out;
}

/**
 * Whether a new score is worth publishing. Scores drift a little every day; republishing every
 * drift would rewrite every advisory and product file daily. A score is replaced when the
 * percentile moves by a point, the probability by a tenth (and at least 0.001), or it crosses
 * the signal threshold.
 */
export function epssMoved(old: EpssScore, next: EpssScore): boolean {
  const crossed =
    old.percentile >= EPSS_SIGNAL_PERCENTILE !== next.percentile >= EPSS_SIGNAL_PERCENTILE;
  const delta = Math.abs(next.score - old.score);
  return (
    crossed ||
    Math.abs(next.percentile - old.percentile) >= 0.01 ||
    (delta >= 0.001 && delta >= old.score * 0.1)
  );
}

/** Merges fresh scores into the stored ones; wanted limits the store to the CVEs of the feed. */
export function mergeEpss(
  stored: EpssScores,
  fresh: ReadonlyMap<string, EpssScore>,
  wanted: ReadonlySet<string>,
): EpssScores {
  const scores: Record<string, EpssScore> = {};
  for (const id of [...wanted].sort()) {
    const old = stored.scores[id];
    const next = fresh.get(id);
    if (next !== undefined && (old === undefined || epssMoved(old, next))) scores[id] = next;
    else if (old !== undefined) scores[id] = old;
  }
  return { scores };
}

/** Reads one CVE from NVD; undefined when NVD does not know it. */
export async function fetchNvd(
  http: Http,
  id: string,
  day: string,
): Promise<NvdRecord | undefined> {
  const response = await http.json<unknown>(`${NVD_API}?cveId=${encodeURIComponent(id)}`);
  return response === undefined ? undefined : trimNvd(response.data, id, day);
}

/** Whether a CVE should be asked at NVD this run. */
export function nvdDue(record: NvdRecord | undefined, today: string): boolean {
  if (record === undefined) return true;
  if (record.metrics.length > 0) return false;
  const age = (Date.parse(today) - Date.parse(record.fetched_at)) / 86_400_000;
  return age >= NVD_RETRY_DAYS;
}

function levelFromWord(word: string | null): Severity['level'] | undefined {
  switch (word?.toUpperCase()) {
    case 'CRITICAL':
      return 'critical';
    case 'HIGH':
      return 'high';
    case 'MEDIUM':
      return 'medium';
    case 'LOW':
      return 'low';
    default:
      return undefined;
  }
}

/** NVD's own (Primary) score first, else another source's, newest CVSS version first. */
export function nvdSeverity(record: NvdRecord | undefined): Severity | undefined {
  if (record === undefined) return undefined;
  const ordered = [
    ...record.metrics.filter((m) => m.type === 'Primary'),
    ...record.metrics.filter((m) => m.type !== 'Primary'),
  ];
  const metric = ordered.find((m) => m.score >= 0 && m.score <= 10);
  if (metric === undefined) return undefined;
  return {
    level: levelFromWord(metric.severity) ?? levelFromScore(metric.score),
    score: metric.score,
    vector: metric.vector !== null && /^CVSS:[0-9.]+\//.test(metric.vector) ? metric.vector : null,
    source: 'nvd',
  };
}

/** KEV status of a cluster: listed when any of its CVE ids is in the catalog. */
export function kevOf(cves: readonly string[], kev: KevCatalog | undefined): Advisory['kev'] {
  if (kev === undefined) return { listed: false, added_at: null, checked: false };
  const dates = cves
    .map((id) => kev.entries[id])
    .filter((d): d is string => d !== undefined)
    .sort();
  const first = dates[0];
  return first === undefined
    ? { listed: false, added_at: null, checked: true }
    : { listed: true, added_at: first, checked: true };
}

/** EPSS of a cluster: the highest score among its CVE ids, or null. */
export function epssOf(cves: readonly string[], epss: EpssScores): Advisory['epss'] {
  let best: EpssScore | undefined;
  for (const id of cves) {
    const score = epss.scores[id];
    if (score !== undefined && (best === undefined || score.score > best.score)) best = score;
  }
  // Key order follows the schema, whatever order the stored file has.
  return best === undefined
    ? null
    : { score: best.score, percentile: best.percentile, date: best.date };
}

/** Attribution records for the enrichment a cluster received. */
export function enrichmentSources(
  cves: readonly string[],
  enrichment: Enrichment,
  /** The CVE whose NVD record gave the severity, if any. */
  nvdId: string | undefined,
): SourceRef[] {
  const out: SourceRef[] = [];
  for (const id of cves) {
    if (enrichment.kev?.entries[id] !== undefined) {
      out.push({
        type: 'kev',
        id,
        url: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${id}`,
        license: 'CC0-1.0',
      });
    }
    if (enrichment.epss.scores[id] !== undefined) {
      out.push({ type: 'epss', id, url: `${EPSS_API}?cve=${id}`, license: 'FIRST-EPSS' });
    }
    if (id === nvdId) {
      out.push({
        type: 'nvd',
        id,
        url: `https://nvd.nist.gov/vuln/detail/${id}`,
        license: 'NVD-TOU',
      });
    }
  }
  return out;
}

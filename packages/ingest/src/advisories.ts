import { createHash } from 'node:crypto';
import type { Advisory, AffectedProduct, FeedNote } from '@advisorydeck/contract';
import {
  EPSS_SIGNAL_PERCENTILE,
  enrichmentSources,
  epssOf,
  kevOf,
  noEnrichment,
  nvdSeverity,
  type Enrichment,
} from './enrich.ts';
import type { ProductClaim, RecordFacts, Reference, Severity, SourceRef } from './normalize.ts';
import { stableJson } from './store.ts';
import { isBounded } from './versions.ts';

const TITLE_MAX = 300;
const SUMMARY_MAX = 4000;

function truncate(text: string, max: number): string {
  return text.length <= max ? text : `${text.slice(0, max - 3).trimEnd()}...`;
}

function firstSentence(text: string): string {
  const match = /^(.+?[.!?])(\s|$)/s.exec(text);
  return (match?.[1] ?? text).replace(/\s+/g, ' ').trim();
}

/** Sorts CVE ids by year then number (CVE-2026-9999 before CVE-2026-10000), others by text. */
export function compareIds(a: string, b: string): number {
  const ca = /^CVE-(\d+)-(\d+)$/.exec(a);
  const cb = /^CVE-(\d+)-(\d+)$/.exec(b);
  if (ca !== null && cb !== null) {
    return Number(ca[1]) - Number(cb[1]) || Number(ca[2]) - Number(cb[2]);
  }
  if (ca !== null) return -1;
  if (cb !== null) return 1;
  return a < b ? -1 : a > b ? 1 : 0;
}

/** The CVE ids of a cluster, in id order. */
export function cveIdsOf(ids: readonly string[]): string[] {
  return ids.filter((id) => /^CVE-\d{4}-\d{4,}$/.test(id)).sort(compareIds);
}

/** Groups records whose ids link to each other (a GHSA naming its CVE) into clusters. */
export function clusterRecords(records: readonly RecordFacts[]): string[][] {
  const parent = new Map<string, string>();
  const find = (id: string): string => {
    let root = id;
    while (parent.get(root) !== undefined && parent.get(root) !== root) {
      root = parent.get(root) ?? root;
    }
    parent.set(id, root);
    return root;
  };
  const union = (a: string, b: string) => {
    const ra = find(a);
    const rb = find(b);
    if (ra !== rb) parent.set(compareIds(ra, rb) <= 0 ? rb : ra, compareIds(ra, rb) <= 0 ? ra : rb);
  };
  for (const record of records) {
    if (!parent.has(record.id)) parent.set(record.id, record.id);
    for (const link of record.links) {
      if (!parent.has(link)) parent.set(link, link);
      union(record.id, link);
    }
  }
  const groups = new Map<string, string[]>();
  for (const id of parent.keys()) {
    const root = find(id);
    groups.set(root, [...(groups.get(root) ?? []), id]);
  }
  return [...groups.values()]
    .map((ids) => ids.sort(compareIds))
    .sort((a, b) => compareIds(a[0] ?? '', b[0] ?? ''));
}

/**
 * Picks one claim per product: the most trusted source (catalog order) whose ranges are all
 * bounded, else the most trusted one with any ranges, else unknown (empty).
 */
export function pickRanges(claims: readonly ProductClaim[]): AffectedProduct[] {
  const bySlug = new Map<string, ProductClaim[]>();
  for (const claim of claims) bySlug.set(claim.slug, [...(bySlug.get(claim.slug) ?? []), claim]);
  return [...bySlug.keys()].sort().map((slug) => {
    const ordered = [...(bySlug.get(slug) ?? [])].sort((a, b) => a.rank - b.rank);
    const best =
      ordered.find((c) => c.ranges.length > 0 && c.ranges.every(isBounded)) ??
      ordered.find((c) => c.ranges.length > 0);
    return { product: slug, ranges: best?.ranges ?? [] };
  });
}

/**
 * Material revision: changes only with severity level, ranges, a KEV listing, the EPSS signal
 * (crossing the percentile threshold) or the reviewed note. Titles, descriptions, references,
 * dates, scores within a level and the KEV "checked" flag do not count, so trivial upstream edits
 * never make an image post again.
 */
export function revisionOf(advisory: Omit<Advisory, 'revision'>): string {
  const material = {
    severity: advisory.severity.level,
    affected: advisory.affected,
    kev: advisory.kev.listed,
    // Below the threshold and unknown hash the same (null, as before scores were filled), so
    // filling or refreshing a score never changes a revision; crossing the threshold does.
    epss:
      advisory.epss !== null && advisory.epss.percentile >= EPSS_SIGNAL_PERCENTILE ? true : null,
    note: advisory.note,
  };
  return `sha256:${createHash('sha256').update(stableJson(material)).digest('hex')}`;
}

/** Builds one advisory from the records of a cluster, or undefined when no catalog product is named. */
export function buildAdvisory(
  ids: readonly string[],
  facts: ReadonlyMap<string, RecordFacts>,
  notes: ReadonlyMap<string, FeedNote | null>,
  enrichment: Enrichment = noEnrichment,
): Advisory | undefined {
  const members = ids
    .map((id) => facts.get(id))
    .filter((f): f is RecordFacts => f !== undefined)
    .sort((a, b) => (a.kind === b.kind ? compareIds(a.id, b.id) : a.kind === 'cve' ? -1 : 1));
  const claims = members.flatMap((m) => m.claims);
  if (claims.length === 0) return undefined;
  const affected = pickRanges(claims);
  const [firstAffected, ...restAffected] = affected;
  if (firstAffected === undefined) return undefined;

  const id = [...ids].sort(compareIds)[0];
  if (id === undefined) return undefined;
  const cves = members.filter((m) => m.kind === 'cve');
  const ghsas = members.filter((m) => m.kind === 'ghsa');
  const pick = <T>(get: (m: RecordFacts) => T | undefined): T | undefined => {
    for (const m of members) {
      const value = get(m);
      if (value !== undefined) return value;
    }
    return undefined;
  };
  const description = pick((m) => m.description);
  const title = truncate(
    pick((m) => m.title) ?? (description === undefined ? id : firstSentence(description)),
    TITLE_MAX,
  );
  const cveIds = cveIdsOf(ids);
  // Severity chain: a CNA score, else a GitHub score, else NVD's, else a GitHub rating without
  // a score, else unknown.
  const recorded = [...cves, ...ghsas]
    .map((m) => m.severity)
    .filter((s): s is Severity => s !== undefined);
  const nvdId = recorded.some((s) => s.score !== null)
    ? undefined
    : cveIds.find((cve) => nvdSeverity(enrichment.nvd.get(cve)) !== undefined);
  const severity: Severity = recorded.find((s) => s.score !== null) ??
    (nvdId === undefined ? undefined : nvdSeverity(enrichment.nvd.get(nvdId))) ??
    recorded[0] ?? {
      level: 'unknown',
      score: null,
      vector: null,
      source: 'none',
    };
  const times = (get: (m: RecordFacts) => string | undefined) =>
    members
      .map(get)
      .filter((t): t is string => t !== undefined)
      .sort();
  const published = times((m) => m.published)[0] ?? times((m) => m.modified)[0];
  const modified = times((m) => m.modified).at(-1) ?? published;
  if (published === undefined || modified === undefined) return undefined;

  const references: Reference[] = [];
  const seen = new Set<string>();
  for (const ref of members.flatMap((m) => m.references)) {
    if (!seen.has(ref.url)) {
      seen.add(ref.url);
      references.push(ref);
    }
  }
  const sources = [
    ...members.map((m) => m.source),
    ...enrichmentSources(cveIds, enrichment, nvdId),
  ].sort((a, b) => (a.type === b.type ? compareIds(a.id, b.id) : a.type < b.type ? -1 : 1));
  const [firstSource, ...restSources] = sources;
  if (firstSource === undefined) return undefined;
  const cwes = [...new Set(members.flatMap((m) => m.cwes))].sort(
    (a, b) => Number(a.slice(4)) - Number(b.slice(4)),
  );

  const draft: Omit<Advisory, 'revision'> = {
    id,
    aliases: ids.filter((other) => other !== id),
    title,
    summary: truncate(description ?? title, SUMMARY_MAX),
    published_at: published,
    modified_at: modified < published ? published : modified,
    severity,
    kev: kevOf(cveIds, enrichment.kev),
    epss: epssOf(cveIds, enrichment.epss),
    ...(cwes.length > 0 ? { cwes } : {}),
    affected: [firstAffected, ...restAffected],
    references,
    sources: [firstSource, ...restSources] as [SourceRef, ...SourceRef[]],
    note: notes.get(id) ?? null,
  };
  // Key order follows the schema, so the files read in the same order as the contract.
  const { note, ...rest } = draft;
  return { ...rest, revision: revisionOf(draft), note };
}

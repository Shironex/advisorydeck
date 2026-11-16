import { existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import type { Http } from './http.ts';
import { trimCve, type CveRecord } from './records.ts';
import type { IngestState, Store } from './store.ts';
import { extractZipEntry, readZipBuffer, readZipFile } from './zip.ts';

/**
 * cvelistV5 (github.com/CVEProject/cvelistV5), as published in its GitHub releases:
 * - every hour a release cve_<day>_<HH>00Z with <day>_delta_CVEs_at_<HH>00Z.zip, holding every
 *   record changed since that day's midnight baseline (cumulative within the day);
 * - after midnight a release cve_<day>_at_end_of_day with <day>_delta_CVEs_at_end_of_day.zip,
 *   the whole day's changes;
 * - every hourly release also carries <day>_all_CVEs_at_midnight.zip.zip, the full list (a zip
 *   holding cves.zip, several hundred MB).
 * Releases are kept for about six weeks. Records are used under the CVE Program Terms of Use.
 */
export const CVELIST_REPO = 'CVEProject/cvelistV5';
const RELEASES = `https://api.github.com/repos/${CVELIST_REPO}/releases?per_page=100`;
const RAW = `https://raw.githubusercontent.com/${CVELIST_REPO}/main/cves`;

interface ReleaseAsset {
  name: string;
  browser_download_url: string;
}

interface Release {
  tag_name: string;
  assets: ReleaseAsset[];
}

export interface DeltaRelease {
  tag: string;
  day: string;
  /** "end_of_day" or the hour (0000 to 2300). */
  hour: string;
  delta: ReleaseAsset | undefined;
  baseline: ReleaseAsset | undefined;
}

export interface CvelistContext {
  http: Http;
  store: Store;
  state: IngestState;
  /** Decides whether a record belongs in the store (catalog product or wanted alias, after the floor). */
  keep: (record: CveRecord) => boolean;
  log: (message: string) => void;
}

export interface CvelistResult {
  releases: string[];
  seen: number;
  kept: number;
  removed: number;
}

export function parseReleaseTag(tag: string): { day: string; hour: string } | undefined {
  const match = /^cve_(\d{4}-\d{2}-\d{2})_(?:(\d{4})Z|at_end_of_day)$/.exec(tag);
  if (match?.[1] === undefined) return undefined;
  return { day: match[1], hour: match[2] ?? 'end_of_day' };
}

async function listReleases(http: Http, oldestDay: string | null): Promise<DeltaRelease[]> {
  const out: DeltaRelease[] = [];
  let url: string | undefined = RELEASES;
  while (url !== undefined) {
    const page: { data: Release[]; next: string | undefined } | undefined =
      await http.json<Release[]>(url);
    if (page === undefined) break;
    for (const release of page.data) {
      const parsed = parseReleaseTag(release.tag_name);
      if (parsed === undefined) continue;
      out.push({
        tag: release.tag_name,
        ...parsed,
        delta: release.assets.find((a) => /_delta_CVEs_at_.*\.zip$/.test(a.name)),
        baseline: release.assets.find((a) => /_all_CVEs_at_midnight\.zip(\.zip)?$/.test(a.name)),
      });
    }
    const last = out.at(-1);
    url =
      oldestDay === null || (last !== undefined && last.day < oldestDay) ? undefined : page.next;
  }
  return out;
}

/** The delta releases to apply after the cursor: each full day's end-of-day file, then today's latest hour. */
export function planDeltas(
  releases: readonly DeltaRelease[],
  cursor: IngestState['cvelist'],
): DeltaRelease[] {
  if (cursor.day === null) return [];
  const byDay = new Map<string, DeltaRelease[]>();
  for (const release of releases) {
    if (release.delta === undefined || release.day < cursor.day) continue;
    byDay.set(release.day, [...(byDay.get(release.day) ?? []), release]);
  }
  const plan: DeltaRelease[] = [];
  for (const day of [...byDay.keys()].sort()) {
    const list = byDay.get(day) ?? [];
    const best =
      list.find((r) => r.hour === 'end_of_day') ??
      [...list].sort((a, b) => (a.hour < b.hour ? 1 : -1))[0];
    if (best !== undefined && best.tag !== cursor.release) plan.push(best);
  }
  return plan;
}

function apply(ctx: CvelistContext, text: string, result: CvelistResult): void {
  result.seen += 1;
  const record = trimCve(JSON.parse(text) as unknown);
  if (record === undefined) return;
  const id = record.cveMetadata.cveId;
  const stored = ctx.store.cve.get(id);
  if (record.cveMetadata.state !== 'PUBLISHED' || !ctx.keep(record)) {
    if (stored !== undefined) {
      ctx.store.cve.delete(id);
      result.removed += 1;
    }
    return;
  }
  const before = stored?.cveMetadata.dateUpdated ?? '';
  if (stored !== undefined && (record.cveMetadata.dateUpdated ?? '') < before) return;
  ctx.store.cve.set(id, record);
  result.kept += 1;
}

/** Applies the delta zips published since the cursor and moves the cursor. */
export async function ingestCvelistDeltas(ctx: CvelistContext): Promise<CvelistResult> {
  const result: CvelistResult = { releases: [], seen: 0, kept: 0, removed: 0 };
  const cursor = ctx.state.cvelist;
  if (cursor.day === null) {
    throw new Error('cvelistV5 has no cursor yet: run once with --backfill');
  }
  const releases = await listReleases(ctx.http, cursor.day);
  const oldest = releases.at(-1)?.day;
  if (oldest !== undefined && oldest > cursor.day) {
    throw new Error(
      `cvelistV5 releases start at ${oldest}, after the cursor ${cursor.day}: run with --backfill`,
    );
  }
  for (const release of planDeltas(releases, cursor)) {
    if (release.delta === undefined) continue;
    const zip = await ctx.http.bytes(release.delta.browser_download_url);
    if (zip === undefined) throw new Error(`missing asset ${release.delta.name}`);
    await readZipBuffer(
      zip,
      (name) => name.endsWith('.json'),
      (_name, data) => {
        apply(ctx, data.toString('utf8'), result);
      },
    );
    ctx.state.cvelist = { day: release.day, release: release.tag };
    result.releases.push(release.tag);
  }
  return result;
}

const ASSIGNER = /"assignerShortName"\s*:\s*"([^"]+)"/;
const CVE_FILE = /CVE-(\d{4})-(\d+)\.json$/;

/**
 * Rebuilds the CVE store from a midnight baseline (downloaded into cacheDir, or a file already on
 * disk), then sets the cursor to that day so the next delta run continues from it.
 */
export async function backfillCvelist(
  ctx: CvelistContext & {
    cacheDir: string;
    baselineFile: string | undefined;
    assigners: ReadonlySet<string>;
    wanted: ReadonlySet<string>;
    minYear: number;
  },
): Promise<CvelistResult & { baselineDay: string }> {
  mkdirSync(ctx.cacheDir, { recursive: true });
  let outer = ctx.baselineFile;
  let day: string | undefined;
  if (outer === undefined) {
    const releases = await listReleases(ctx.http, null);
    const latest = releases.find((r) => r.baseline !== undefined);
    if (latest?.baseline === undefined) throw new Error('no midnight baseline found');
    day = latest.day;
    outer = join(ctx.cacheDir, latest.baseline.name);
    if (!existsSync(outer)) {
      ctx.log(`downloading ${latest.baseline.name}`);
      await ctx.http.download(latest.baseline.browser_download_url, outer);
    }
  }
  day ??= /(\d{4}-\d{2}-\d{2})_all_CVEs/.exec(outer)?.[1];
  if (day === undefined) throw new Error(`cannot tell the day of ${outer}`);
  const inner = join(ctx.cacheDir, `${day}_cves.zip`);
  if (!existsSync(inner)) {
    ctx.log(`extracting ${outer}`);
    await extractZipEntry(outer, (name) => name.endsWith('.zip'), inner);
  }
  const result: CvelistResult = { releases: [], seen: 0, kept: 0, removed: 0 };
  ctx.log(`scanning ${inner}`);
  await readZipFile(
    inner,
    (name) => {
      const match = CVE_FILE.exec(name);
      return match !== null && Number(match[1]) >= ctx.minYear;
    },
    (name, data) => {
      const text = data.toString('utf8');
      const id = CVE_FILE.exec(name)?.[0].slice(0, -5) ?? '';
      const assigner = ASSIGNER.exec(text)?.[1] ?? '';
      if (
        ctx.assigners.has(assigner) ||
        ctx.wanted.has(id) ||
        ctx.store.cve.get(id) !== undefined
      ) {
        apply(ctx, text, result);
      }
    },
  );
  ctx.state.cvelist = { day, release: null };
  return { ...result, baselineDay: day };
}

/** Raw URL of one record in the repository (cves/2026/120xxx/CVE-2026-120154.json). */
export function cveRawUrl(id: string): string | undefined {
  const match = /^CVE-(\d{4})-(\d+)$/.exec(id);
  if (match?.[1] === undefined || match[2] === undefined) return undefined;
  return `${RAW}/${match[1]}/${Math.floor(Number(match[2]) / 1000)}xxx/${id}.json`;
}

/** Fetches one record (for a CVE a GHSA names that no delta brought in). */
export async function fetchCve(http: Http, id: string): Promise<CveRecord | undefined> {
  const url = cveRawUrl(id);
  if (url === undefined) return undefined;
  const response = await http.json<unknown>(url);
  return response === undefined ? undefined : trimCve(response.data);
}

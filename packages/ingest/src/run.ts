import { join } from 'node:path';
import {
  loadCatalog,
  loadNotes,
  repoRoot,
  toFeedNote,
  type Advisory,
  type FeedNote,
} from '@advisorydeck/contract';
import { buildAdvisory, clusterRecords } from './advisories.ts';
import { backfillCvelist, fetchCve, ingestCvelistDeltas } from './cvelist.ts';
import { fetchBranches } from './endoflife.ts';
import { ghsaQueries, ingestGhsa } from './ghsa.ts';
import type { Http } from './http.ts';
import { cveFacts, ghsaFacts, isoTime, type Catalogue, type RecordFacts } from './normalize.ts';
import { writeOutputs, writeQuality, type OutputReport } from './output.ts';
import type { CveRecord } from './records.ts';
import { buildSourceIndex } from './source-index.ts';
import { Store, type IngestState } from './store.ts';

export type SourceName = 'cve' | 'ghsa' | 'branches';

export interface RunOptions {
  http: Http;
  /** Repository root: catalog, notes and schemas are read from here. */
  root?: string;
  /** Where outputs, source records and the state file go (default <root>/data). */
  dataDir?: string;
  now?: Date;
  log?: (message: string) => void;
  /** Rebuild the CVE store from the midnight baseline before applying deltas. */
  backfill?: boolean;
  baselineFile?: string | undefined;
  cacheDir?: string;
  /** Published floor (YYYY-MM-DD); default: the stored one, or one year before now. */
  since?: string | undefined;
  /** Skip every network source and rebuild the outputs from the stored records. */
  offline?: boolean;
  skip?: ReadonlySet<SourceName>;
}

export interface RunReport {
  advisories: number;
  output: OutputReport;
  warnings: string[];
  errors: string[];
  state: IngestState;
}

function yearBefore(now: Date): string {
  const d = new Date(now);
  d.setUTCFullYear(d.getUTCFullYear() - 1);
  return d.toISOString().slice(0, 10);
}

function cvePublished(record: CveRecord): string {
  return isoTime(record.cveMetadata.datePublished) ?? '';
}

export async function runIngest(options: RunOptions): Promise<RunReport> {
  const root = options.root ?? repoRoot();
  const dataDir = options.dataDir ?? join(root, 'data');
  const now = options.now ?? new Date();
  const log = options.log ?? (() => undefined);
  const skip = options.skip ?? new Set<SourceName>();
  const warnings: string[] = [];
  const errors: string[] = [];

  const catalog = loadCatalog(root);
  if (catalog.issues.length > 0) {
    throw new Error(`catalog has issues: ${catalog.issues.map((i) => i.message).join('; ')}`);
  }
  const { index, issues } = buildSourceIndex(catalog.entries);
  if (issues.length > 0)
    throw new Error(`source index: ${issues.map((i) => i.message).join('; ')}`);
  const catalogue: Catalogue = { entries: catalog.entries, index };

  const store = new Store(dataDir);
  const state: IngestState = store.readState() ?? {
    published_floor: options.since ?? yearBefore(now),
    cvelist: { day: null, release: null },
    ghsa: {},
  };
  if (options.since !== undefined) state.published_floor = options.since;
  const floor = state.published_floor;
  function wantedIds(): Set<string> {
    const wanted = new Set<string>();
    for (const record of store.ghsa.items.values()) {
      for (const link of ghsaFacts(record, catalogue).links) {
        if (link.startsWith('CVE-')) wanted.add(link);
      }
    }
    return wanted;
  }
  const initiallyWanted = wantedIds();
  for (const [id, record] of [...store.cve.items]) {
    if (cvePublished(record) < floor && !initiallyWanted.has(id)) store.cve.delete(id);
  }

  if (options.offline !== true) {
    if (!skip.has('ghsa')) {
      try {
        const result = await ingestGhsa(
          { http: options.http, store, state, log },
          ghsaQueries(catalog.entries),
        );
        log(
          `ghsa: ${result.requests} requests, ${result.seen} seen, ${result.stored} stored, ${result.removed} removed`,
        );
      } catch (error) {
        errors.push(`ghsa: ${String(error)}`);
      }
    }
    const wanted = wantedIds();
    const keep = (record: CveRecord) =>
      wanted.has(record.cveMetadata.cveId) ||
      (cvePublished(record) >= floor && cveFacts(record, catalogue).claims.length > 0);
    if (!skip.has('cve')) {
      try {
        const context = { http: options.http, store, state, keep, log };
        if (options.backfill === true) {
          const result = await backfillCvelist({
            ...context,
            cacheDir: options.cacheDir ?? join(root, '.cache', 'ingest'),
            baselineFile: options.baselineFile,
            assigners: new Set(index.cna.keys()),
            wanted,
            minYear: Number(floor.slice(0, 4)) - 2,
          });
          log(`cvelist baseline ${result.baselineDay}: ${result.seen} read, ${result.kept} kept`);
        }
        const result = await ingestCvelistDeltas(context);
        log(
          `cvelist deltas [${result.releases.join(', ')}]: ${result.seen} read, ${result.kept} kept, ${result.removed} removed`,
        );
      } catch (error) {
        errors.push(`cvelist: ${String(error)}`);
      }
      for (const id of [...wanted].sort()) {
        if (store.cve.get(id) !== undefined) continue;
        try {
          const record = await fetchCve(options.http, id);
          if (record?.cveMetadata.state === 'PUBLISHED') store.cve.set(id, record);
        } catch (error) {
          warnings.push(`${id}: ${String(error)}`);
        }
      }
    }
    if (!skip.has('branches')) {
      for (const { product } of catalog.entries) {
        if (
          product.branches.source !== 'endoflife' ||
          product.branches.endoflife_slug === undefined
        ) {
          continue;
        }
        try {
          const branches = await fetchBranches(options.http, product.branches.endoflife_slug);
          if (branches !== undefined) store.branches.set(product.slug, branches);
        } catch (error) {
          warnings.push(`endoflife ${product.slug}: ${String(error)} (kept the stored branches)`);
        }
      }
    }
  }

  const facts = new Map<string, RecordFacts>();
  for (const record of store.cve.items.values()) {
    const f = cveFacts(record, catalogue);
    facts.set(f.id, f);
  }
  for (const record of store.ghsa.items.values()) {
    const f = ghsaFacts(record, catalogue);
    facts.set(f.id, f);
  }

  const notes = new Map<string, FeedNote | null>();
  const loaded = loadNotes(root);
  warnings.push(...loaded.issues.map((i) => `${i.file}: ${i.message}`));
  for (const { note, body } of loaded.notes) notes.set(note.advisory, toFeedNote(note, body));

  const advisories: Advisory[] = [];
  const quality: Record<string, string[]> = {};
  for (const ids of clusterRecords([...facts.values()])) {
    const advisory = buildAdvisory(ids, facts, notes);
    if (advisory === undefined || advisory.published_at < floor) continue;
    advisories.push(advisory);
    const found = ids.flatMap((id) => facts.get(id)?.warnings ?? []);
    if (found.length > 0) quality[advisory.id] = found;
  }

  store.flush();
  const output = writeOutputs({
    dataDir,
    entries: catalog.entries,
    advisories,
    branches: (slug) => store.branches.get(slug) ?? [],
    now: `${now.toISOString().slice(0, 19)}Z`,
    schemaRoot: root,
  });
  writeQuality(dataDir, quality);
  for (const [id, found] of Object.entries(quality)) {
    for (const message of found) warnings.push(`${id}: ${message}`);
  }
  errors.push(...output.issues);
  store.writeState(state);
  return { advisories: advisories.length, output, warnings, errors, state };
}

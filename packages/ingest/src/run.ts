import { join } from 'node:path';
import {
  loadCatalog,
  loadNotes,
  repoRoot,
  toFeedNote,
  type Advisory,
  type FeedNote,
} from '@advisorydeck/contract';
import { buildAdvisory, clusterRecords, cveIdsOf } from './advisories.ts';
import { backfillCvelist, fetchCve, ingestCvelistDeltas } from './cvelist.ts';
import { fetchBranches } from './endoflife.ts';
import {
  EPSS_REFRESH_HOURS,
  fetchEpss,
  fetchKev,
  fetchNvd,
  mergeEpss,
  NVD_MAX_PER_RUN,
  NVD_SPACING_MS,
  nvdDue,
  type Enrichment,
} from './enrich.ts';
import { ghsaQueries, ingestGhsa } from './ghsa.ts';
import type { Http } from './http.ts';
import { cveFacts, ghsaFacts, isoTime, type Catalogue, type RecordFacts } from './normalize.ts';
import { writeOutputs, writeQuality, type OutputReport } from './output.ts';
import type { CveRecord } from './records.ts';
import { buildSourceIndex } from './source-index.ts';
import { Store, type IngestState } from './store.ts';

export type SourceName = 'cve' | 'ghsa' | 'branches' | 'kev' | 'epss' | 'nvd';

export const sourceNames: readonly SourceName[] = ['cve', 'ghsa', 'branches', 'kev', 'epss', 'nvd'];

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

  // Clusters that will be published, before enrichment: the CVEs to enrich come from these.
  const candidates: { ids: string[]; draft: Advisory }[] = [];
  for (const ids of clusterRecords([...facts.values()])) {
    const draft = buildAdvisory(ids, facts, notes);
    if (draft !== undefined && draft.published_at >= floor) candidates.push({ ids, draft });
  }
  const feedCves = new Set(candidates.flatMap(({ ids }) => cveIdsOf(ids)));
  if (options.offline !== true) {
    await enrich({ options, store, state, now, log, warnings, candidates, feedCves, skip });
  }
  store.epss.set(
    'scores',
    mergeEpss(store.epss.get('scores') ?? { scores: {} }, new Map(), feedCves),
  );
  for (const id of [...store.nvd.items.keys()]) if (!feedCves.has(id)) store.nvd.delete(id);
  const enrichment: Enrichment = {
    kev: store.kev.get('catalog'),
    epss: store.epss.get('scores') ?? { scores: {} },
    nvd: store.nvd.items,
  };
  if (enrichment.kev === undefined) {
    warnings.push('the KEV catalog was never read: every advisory is published as not checked');
  }

  const advisories: Advisory[] = [];
  const quality: Record<string, string[]> = {};
  for (const { ids } of candidates) {
    const advisory = buildAdvisory(ids, facts, notes, enrichment);
    if (advisory === undefined) continue;
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

interface EnrichContext {
  options: RunOptions;
  store: Store;
  state: IngestState;
  now: Date;
  log: (message: string) => void;
  warnings: string[];
  candidates: readonly { ids: string[]; draft: Advisory }[];
  feedCves: ReadonlySet<string>;
  skip: ReadonlySet<SourceName>;
}

/** Reads KEV, EPSS and NVD into the store. A failing source keeps what is stored and warns. */
async function enrich(context: EnrichContext): Promise<void> {
  const { options, store, state, now, log, warnings, candidates, feedCves, skip } = context;
  const http = options.http;
  if (!skip.has('kev')) {
    try {
      const catalog = await fetchKev(http);
      store.kev.set('catalog', catalog);
      log(`kev: catalog ${catalog.catalog_version}, ${Object.keys(catalog.entries).length} CVEs`);
    } catch (error) {
      warnings.push(`kev: ${String(error)} (kept the stored catalog)`);
    }
  }
  if (!skip.has('epss')) {
    const stored = store.epss.get('scores') ?? { scores: {} };
    const last = state.epss_fetched_at === undefined ? 0 : Date.parse(state.epss_fetched_at);
    const refresh = now.getTime() - last >= EPSS_REFRESH_HOURS * 3_600_000;
    const ask = [...feedCves].sort().filter((id) => refresh || stored.scores[id] === undefined);
    if (ask.length > 0) {
      try {
        const fresh = await fetchEpss(http, ask);
        store.epss.set('scores', mergeEpss(stored, fresh, feedCves));
        if (refresh) state.epss_fetched_at = `${now.toISOString().slice(0, 19)}Z`;
        log(`epss: asked ${ask.length}, scored ${fresh.size}`);
      } catch (error) {
        warnings.push(`epss: ${String(error)} (kept the stored scores)`);
      }
    }
  }
  if (!skip.has('nvd')) {
    const today = now.toISOString().slice(0, 10);
    const due = candidates
      .filter(({ draft }) => draft.severity.score === null)
      .flatMap(({ ids }) => cveIdsOf(ids))
      .filter((id) => nvdDue(store.nvd.get(id), today));
    for (const [i, id] of due.slice(0, NVD_MAX_PER_RUN).entries()) {
      if (i > 0) await http.pause(NVD_SPACING_MS);
      try {
        const record = await fetchNvd(http, id, today);
        store.nvd.set(id, record ?? { id, fetched_at: today, metrics: [] });
      } catch (error) {
        warnings.push(`nvd ${id}: ${String(error)}`);
        break;
      }
    }
    if (due.length > NVD_MAX_PER_RUN) {
      log(`nvd: ${due.length - NVD_MAX_PER_RUN} CVEs left for the next run`);
    }
  }
}

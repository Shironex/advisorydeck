/**
 * Every read of the feed data goes through this module. Pages and components get plain view
 * objects from here and never reach into contract fields themselves, so a contract change (KEV
 * gaining a "not checked" state, release bundles, new fields) is an edit in this file only.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  loadCatalog,
  loadNotes,
  type Advisory,
  type CuratedNote,
  type FeedNote,
  type Manifest,
  type NoteAction,
  type Product,
  type ProductFeed,
  type VersionRange,
} from '@advisorydeck/contract';
import { dataRoot } from './root.ts';

export type SeverityLevel = 'unknown' | 'low' | 'medium' | 'high' | 'critical';
export const SEVERITY_ORDER: readonly SeverityLevel[] = [
  'critical',
  'high',
  'medium',
  'low',
  'unknown',
];

export type Category = Product['category'];

export const CATEGORY_LABELS: Record<Category, { name: string; blurb: string }> = {
  databases: { name: 'Databases', blurb: 'Relational and key-value stores.' },
  proxies: { name: 'Proxies', blurb: 'Reverse proxies and load balancers.' },
  os: { name: 'OS and kernel', blurb: 'Operating systems and kernels.' },
  paas: { name: 'Platforms', blurb: 'Self-hosted platforms that deploy your apps.' },
  containers: { name: 'Containers', blurb: 'Container engines and tooling.' },
  runtimes: { name: 'Runtimes', blurb: 'Language runtimes.' },
};

export const CATEGORY_ORDER: readonly Category[] = [
  'paas',
  'proxies',
  'databases',
  'containers',
  'os',
  'runtimes',
];

/**
 * KEV state as the site shows it. "not-checked" is distinct from "not-listed": until the KEV
 * catalog has been checked for an advisory, the site must not imply it is not exploited.
 */
export type KevState =
  { state: 'listed'; addedAt: string | null } | { state: 'not-listed' } | { state: 'not-checked' };

/**
 * `listed` is only a real "no" when `checked` is true (schemas/v1/advisory.schema.json): without
 * `checked`, or with it false, the KEV catalog was not read for this advisory.
 */
export function kevState(advisory: Advisory): KevState {
  const { listed, added_at: addedAt, checked } = advisory.kev;
  if (listed) {
    return { state: 'listed', addedAt };
  }
  return checked === true ? { state: 'not-listed' } : { state: 'not-checked' };
}

export interface EpssView {
  /** Probability of exploitation in the next 30 days, 0 to 1. */
  score: number;
  percentile: number;
  date: string;
}

export function epssView(advisory: Advisory): EpssView | null {
  const epss = advisory.epss;
  if (epss === null || typeof epss !== 'object') {
    return null;
  }
  return { score: epss.score, percentile: epss.percentile, date: epss.date };
}

export interface SeverityView {
  level: SeverityLevel;
  score: number | null;
  vector: string | null;
  /** Human label of the record the score came from. */
  sourceLabel: string;
}

const SEVERITY_SOURCE_LABELS: Record<string, string> = {
  cna: 'CVE record (vendor CNA)',
  ghsa: 'GitHub advisory',
  nvd: 'NVD (NIST)',
  vendor: 'Vendor',
  none: 'No score published',
};

export function severityView(advisory: Advisory): SeverityView {
  const level = (SEVERITY_ORDER as readonly string[]).includes(advisory.severity.level)
    ? advisory.severity.level
    : 'unknown';
  return {
    level,
    score: advisory.severity.score,
    vector: advisory.severity.vector,
    sourceLabel: SEVERITY_SOURCE_LABELS[advisory.severity.source] ?? advisory.severity.source,
  };
}

export interface RangeView {
  introduced: string;
  /** Exclusive bound. */
  fixed: string | null;
  /** Inclusive bound, when the source gives the last affected version instead of a fix. */
  lastAffected: string | null;
}

function rangeView(range: VersionRange): RangeView {
  return {
    introduced: range.introduced,
    fixed: range.fixed ?? null,
    lastAffected: range.last_affected ?? null,
  };
}

export interface AffectedView {
  slug: string;
  name: string;
  /** Empty means the affected versions are unknown: say "check manually", never "not affected". */
  ranges: RangeView[];
}

/** Every fix version listed for one product, newest branch first as published. */
export function fixesOf(affected: AffectedView): string[] {
  return affected.ranges.flatMap((range) => (range.fixed === null ? [] : [range.fixed]));
}

export type NoteState = 'none' | 'draft' | 'reviewed' | 'disputed' | 'superseded';

export interface NoteView {
  state: Exclude<NoteState, 'none'>;
  audience: CuratedNote['audience'];
  exposure: CuratedNote['exposure'];
  assumptions: string[];
  actions: NoteAction[];
  authorship: CuratedNote['authorship'];
  writtenBy: string | null;
  reviewedBy: string | null;
  reviewedAt: string | null;
  /** Markdown, rendered with the safe subset in markdown.ts. */
  body: string;
}

export interface SourceRecordView {
  type: string;
  id: string;
  url: string;
  license: string;
}

export interface AdvisoryView {
  id: string;
  aliases: string[];
  title: string;
  summary: string;
  publishedAt: string;
  modifiedAt: string;
  severity: SeverityView;
  kev: KevState;
  epss: EpssView | null;
  cwes: string[];
  affected: AffectedView[];
  references: { url: string; type: string }[];
  sources: SourceRecordView[];
  note: NoteView | null;
  /** Judgement calls ingest made on messy upstream data (data/quality.json). */
  qualityNotes: string[];
}

export interface BranchView {
  name: string;
  eol: boolean;
  eolDate: string | null;
  latest: string | null;
}

export interface ProductView {
  slug: string;
  name: string;
  category: Category;
  homepage: string;
  description: string | null;
  versionScheme: Product['version_scheme'];
  matchStrategy: Product['match']['strategy'];
  curated: boolean;
  branches: BranchView[];
  branchSource: Product['branches']['source'];
  images: { ref: string; tagPattern: string; note: string | null }[];
  catalogSources: Product['sources'];
  generatedAt: string | null;
  etag: string | null;
  /** Advisories that list this product, newest published first. */
  advisoryIds: string[];
}

export interface SiteData {
  generatedAt: string | null;
  products: ProductView[];
  advisories: Map<string, AdvisoryView>;
  /** Newest published first, then by id. */
  advisoryOrder: string[];
}

function readJson(path: string): unknown {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function noteFromFile(note: CuratedNote, body: string): NoteView {
  return {
    state: note.status,
    audience: note.audience,
    exposure: note.exposure,
    assumptions: note.assumptions,
    actions: note.actions,
    authorship: note.authorship,
    writtenBy: note.written_by ?? null,
    reviewedBy: note.reviewed_by ?? null,
    reviewedAt: note.reviewed_at ?? null,
    body,
  };
}

function noteFromFeed(note: FeedNote): NoteView {
  return {
    state: 'reviewed',
    audience: note.audience,
    exposure: note.exposure,
    assumptions: note.assumptions,
    actions: note.actions,
    authorship: note.authorship,
    writtenBy: null,
    reviewedBy: note.reviewed_by,
    reviewedAt: note.reviewed_at,
    body: note.body,
  };
}

let cached: { root: string; data: SiteData } | undefined;

/** Loads catalog, feed, advisories, notes and quality notes once per build. */
export function loadSiteData(root = dataRoot()): SiteData {
  if (cached?.root === root) {
    return cached.data;
  }
  const catalog = loadCatalog(root);
  if (catalog.issues.length > 0) {
    throw new Error(`catalog problems: ${catalog.issues.map((i) => i.message).join('; ')}`);
  }
  const { notes, issues } = loadNotes(root);
  if (issues.length > 0) {
    throw new Error(`note problems: ${issues.map((i) => `${i.file}: ${i.message}`).join('; ')}`);
  }
  const notesById = new Map(notes.map((entry) => [entry.note.advisory, entry]));
  const feedDir = join(root, 'data/api/v1');
  const manifest = readJson(join(feedDir, 'manifest.json')) as Manifest;
  const quality = readJson(join(root, 'data/quality.json')) as Record<string, string[]>;
  const names = new Map(catalog.entries.map((e) => [e.product.slug, e.product.name]));

  const advisories = new Map<string, AdvisoryView>();
  const advisoriesDir = join(root, 'data/advisories');
  for (const file of readdirSync(advisoriesDir)
    .filter((f) => f.endsWith('.json'))
    .sort()) {
    const advisory = readJson(join(advisoriesDir, file)) as Advisory;
    const noteEntry = notesById.get(advisory.id);
    advisories.set(advisory.id, {
      id: advisory.id,
      aliases: advisory.aliases,
      title: advisory.title,
      summary: advisory.summary,
      publishedAt: advisory.published_at,
      modifiedAt: advisory.modified_at,
      severity: severityView(advisory),
      kev: kevState(advisory),
      epss: epssView(advisory),
      cwes: advisory.cwes ?? [],
      affected: advisory.affected.map((a) => ({
        slug: a.product,
        name: names.get(a.product) ?? a.product,
        ranges: a.ranges.map(rangeView),
      })),
      references: advisory.references,
      sources: advisory.sources,
      note:
        noteEntry !== undefined
          ? noteFromFile(noteEntry.note, noteEntry.body)
          : advisory.note !== null
            ? noteFromFeed(advisory.note)
            : null,
      qualityNotes: quality[advisory.id] ?? [],
    });
  }
  const advisoryOrder = [...advisories.values()]
    .sort((a, b) =>
      a.publishedAt === b.publishedAt
        ? a.id.localeCompare(b.id)
        : a.publishedAt < b.publishedAt
          ? 1
          : -1,
    )
    .map((a) => a.id);

  const products: ProductView[] = catalog.entries.map(({ product }) => {
    const entry = manifest.products[product.slug];
    let feed: ProductFeed | null = null;
    if (entry !== undefined) {
      feed = readJson(join(feedDir, 'products', `${product.slug}.json`)) as ProductFeed;
    }
    const ids = new Set(feed?.advisories.map((a) => a.id) ?? []);
    return {
      slug: product.slug,
      name: product.name,
      category: product.category,
      homepage: product.homepage,
      description: product.description ?? null,
      versionScheme: product.version_scheme,
      matchStrategy: product.match.strategy,
      curated: product.curated,
      branches: (feed?.product.branches ?? []).map((b) => ({
        name: b.name,
        eol: b.eol,
        eolDate: b.eol_date,
        latest: b.latest,
      })),
      branchSource: product.branches.source,
      images: product.images.map((i) => ({
        ref: i.ref,
        tagPattern: i.tag_pattern,
        note: i.note ?? null,
      })),
      catalogSources: product.sources,
      generatedAt: feed?.generated_at ?? null,
      etag: entry?.etag ?? null,
      advisoryIds: advisoryOrder.filter((id) => ids.has(id)),
    };
  });
  products.sort((a, b) => a.name.localeCompare(b.name));

  const data: SiteData = {
    generatedAt: manifest.generated_at,
    products,
    advisories,
    advisoryOrder,
  };
  cached = { root, data };
  return data;
}

export function advisoriesOf(data: SiteData, ids: readonly string[]): AdvisoryView[] {
  return ids.flatMap((id) => {
    const advisory = data.advisories.get(id);
    return advisory === undefined ? [] : [advisory];
  });
}

export function productsIn(data: SiteData, category: Category): ProductView[] {
  return data.products.filter((p) => p.category === category);
}

export function categoriesInUse(data: SiteData): Category[] {
  return CATEGORY_ORDER.filter((c) => data.products.some((p) => p.category === c));
}

export function countBySeverity(
  advisories: readonly AdvisoryView[],
): Record<SeverityLevel, number> {
  const counts: Record<SeverityLevel, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    unknown: 0,
  };
  for (const advisory of advisories) {
    counts[advisory.severity.level] += 1;
  }
  return counts;
}

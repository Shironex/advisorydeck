import { readdirSync, readFileSync, rmSync } from 'node:fs';
import { basename, join } from 'node:path';
import {
  etagOf,
  feedLayout,
  validateAgainst,
  type Advisory,
  type CatalogEntry,
  type Manifest,
  type ProductFeed,
  type Upstream,
} from '@advisorydeck/contract';
import type { BranchRecord } from './records.ts';
import { dataLayout, writeIfChanged } from './store.ts';

export interface OutputReport {
  advisoriesWritten: number;
  advisoriesRemoved: number;
  productsChanged: string[];
  manifestChanged: boolean;
  issues: string[];
}

/** Published JSON: two-space indent, final newline, keys in schema order. */
export function publishedJson(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function readJson(path: string): unknown {
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as unknown;
  } catch {
    return undefined;
  }
}

/** The catalog's upstream status in schema key order, so the published bytes never depend on YAML order. */
function upstreamOf(upstream: Upstream): Upstream {
  return {
    status: upstream.status,
    ...(upstream.since === undefined ? {} : { since: upstream.since }),
    ...(upstream.note === undefined ? {} : { note: upstream.note }),
  };
}

/** Newest published first, then by id, so the order never depends on upstream order. */
export function compareAdvisories(a: Advisory, b: Advisory): number {
  if (a.published_at !== b.published_at) return a.published_at < b.published_at ? 1 : -1;
  return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
}

/**
 * Writes data/advisories/<id>.json, data/api/v1/products/<slug>.json and data/api/v1/manifest.json.
 * Timestamps only move when the content they describe changes, so a rerun with no upstream change
 * leaves every byte as it was.
 */
export function writeOutputs(options: {
  dataDir: string;
  entries: readonly CatalogEntry[];
  advisories: readonly Advisory[];
  branches: (slug: string) => BranchRecord[];
  now: string;
  schemaRoot?: string;
}): OutputReport {
  const { dataDir, now } = options;
  const report: OutputReport = {
    advisoriesWritten: 0,
    advisoriesRemoved: 0,
    productsChanged: [],
    manifestChanged: false,
    issues: [],
  };
  const valid: Advisory[] = [];
  for (const advisory of options.advisories) {
    const problems = validateAgainst('advisory', advisory, options.schemaRoot);
    if (problems.length > 0) {
      report.issues.push(...problems.map((p) => `${advisory.id}: ${p}`));
    } else {
      valid.push(advisory);
    }
  }
  valid.sort(compareAdvisories);

  const advisoriesDir = join(dataDir, dataLayout.advisories);
  const ids = new Set(valid.map((a) => a.id));
  for (const advisory of valid) {
    if (writeIfChanged(join(advisoriesDir, `${advisory.id}.json`), publishedJson(advisory))) {
      report.advisoriesWritten += 1;
    }
  }
  let existing: string[] = [];
  try {
    existing = readdirSync(advisoriesDir);
  } catch {
    // first run
  }
  for (const name of existing) {
    if (name.endsWith('.json') && !ids.has(basename(name, '.json'))) {
      rmSync(join(advisoriesDir, name));
      report.advisoriesRemoved += 1;
    }
  }

  const apiDir = join(dataDir, dataLayout.api);
  const manifestPath = join(apiDir, feedLayout.manifest);
  const previousManifest = readJson(manifestPath) as Manifest | undefined;
  const products: Manifest['products'] = {};
  const entries = [...options.entries].sort((a, b) => (a.product.slug < b.product.slug ? -1 : 1));
  for (const { product } of entries) {
    const path = join(apiDir, feedLayout.productFeed(product.slug));
    const previous = readJson(path) as ProductFeed | undefined;
    const body: Omit<ProductFeed, 'generated_at'> = {
      schema: 'advisorydeck/v1/product-feed',
      product: {
        slug: product.slug,
        name: product.name,
        category: product.category,
        homepage: product.homepage,
        version_scheme: product.version_scheme,
        ...(product.upstream === undefined ? {} : { upstream: upstreamOf(product.upstream) }),
        branches: options.branches(product.slug).map((b) => ({
          name: b.name,
          eol: b.eol,
          eol_date: b.eol_date,
          latest: b.latest,
        })),
      },
      advisories: valid.filter((a) => a.affected.some((x) => x.product === product.slug)),
    };
    let unchanged = false;
    if (previous !== undefined) {
      unchanged =
        publishedJson({ ...previous, generated_at: undefined }) ===
        publishedJson({ ...body, generated_at: undefined });
    }
    const generatedAt = unchanged && previous !== undefined ? previous.generated_at : now;
    const feed: ProductFeed = {
      schema: body.schema,
      generated_at: generatedAt,
      product: body.product,
      advisories: body.advisories,
    };
    const problems = validateAgainst('product-feed', feed, options.schemaRoot);
    if (problems.length > 0) {
      report.issues.push(...problems.map((p) => `products/${product.slug}.json: ${p}`));
    }
    const text = publishedJson(feed);
    if (writeIfChanged(path, text)) report.productsChanged.push(product.slug);
    products[product.slug] = {
      updated_at: generatedAt,
      etag: etagOf(text),
      advisories: feed.advisories.length,
    };
  }

  let productFiles: string[] = [];
  try {
    productFiles = readdirSync(join(apiDir, 'products'));
  } catch {
    // first run
  }
  for (const name of productFiles) {
    if (name.endsWith('.json') && products[basename(name, '.json')] === undefined) {
      rmSync(join(apiDir, 'products', name));
      report.productsChanged.push(basename(name, '.json'));
    }
  }

  const sameProducts =
    previousManifest !== undefined &&
    publishedJson(previousManifest.products) === publishedJson(products);
  const manifest: Manifest = {
    schema: 'advisorydeck/v1/manifest',
    generated_at: sameProducts ? previousManifest.generated_at : now,
    products,
  };
  report.issues.push(
    ...validateAgainst('manifest', manifest, options.schemaRoot).map((p) => `manifest.json: ${p}`),
  );
  report.manifestChanged = writeIfChanged(manifestPath, publishedJson(manifest));
  return report;
}

/**
 * data/quality.json: per published advisory, the judgement calls normalization made on messy
 * upstream data (contradicting ranges, unreadable versions). Sorted, so reruns are stable.
 */
export function writeQuality(
  dataDir: string,
  quality: Readonly<Record<string, string[]>>,
): boolean {
  const ids = Object.keys(quality).sort();
  const body = Object.fromEntries(ids.map((id) => [id, [...new Set(quality[id])].sort()]));
  return writeIfChanged(join(dataDir, dataLayout.quality), publishedJson(body));
}

import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/** Version of the published feed contract. A breaking change means a new version and a new folder. */
export const FEED_VERSION = 'v1';

/** Base of every schema $id; the files live in schemas/v1/. */
export const SCHEMA_BASE =
  'https://raw.githubusercontent.com/Shironex/advisorydeck/main/schemas/v1';

/** Paths relative to the repository root. */
export const repoLayout = {
  catalogDir: 'catalog',
  schemasDir: `schemas/${FEED_VERSION}`,
  notesDir: 'notes',
  correctionsDir: 'corrections',
  dataDir: 'data',
  advisoriesDir: 'data/advisories',
  /** The v1 feed as ingest writes it; the site publishes this folder as api/v1/. */
  feedDir: `data/api/${FEED_VERSION}`,
  fixturesDir: 'fixtures',
} as const;

/** Paths of the published feed, relative to the feed base URL (for example https://host/api/v1/). */
export const feedLayout = {
  basePath: `api/${FEED_VERSION}/`,
  manifest: 'manifest.json',
  productFeed: (slug: string): string => `products/${slug}.json`,
} as const;

/** Where ingest writes one normalized advisory, relative to the repository root. */
export function advisoryFile(id: string): string {
  return `${repoLayout.advisoriesDir}/${id}.json`;
}

/** Absolute path of the repository root (this file sits in packages/contract/src). */
export function repoRoot(): string {
  return resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
}

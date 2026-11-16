import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { isDeepStrictEqual } from 'node:util';
import { basename, join } from 'node:path';
import { loadCatalog } from './catalog.ts';
import { listFiles, parseYaml, relativePath } from './files.ts';
import type { Advisory, ImageConfig, Manifest, ProductFeed } from './generated/types.ts';
import { imageConfigProblems } from './image-config.ts';
import type { Issue } from './issues.ts';
import { feedLayout, repoLayout, repoRoot } from './layout.ts';
import { loadNotes, readNote, toFeedNote } from './notes.ts';
import { type DocumentSchema, validateAgainst } from './schemas.ts';

export interface RepositoryReport {
  issues: Issue[];
  counts: { products: number; notes: number; fixtures: number; published: number };
}

/** sha256 etag of exact file bytes, as the manifest records it. */
export function etagOf(bytes: Buffer | string): string {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function readData(path: string): unknown {
  const text = readFileSync(path, 'utf8');
  return path.endsWith('.json') ? (JSON.parse(text) as unknown) : parseYaml(text);
}

/**
 * Checks everything committed data must satisfy: the catalog, the notes and the fixtures that
 * the other workspaces build against. Returns every problem instead of stopping at the first.
 */
export function checkRepository(root = repoRoot()): RepositoryReport {
  const issues: Issue[] = [];
  const catalog = loadCatalog(root);
  issues.push(...catalog.issues);
  const slugs = new Set(catalog.entries.map((entry) => entry.product.slug));

  const notes = loadNotes(root);
  issues.push(...notes.issues);
  for (const { file, note } of notes.notes) {
    for (const slug of note.products) {
      if (!slugs.has(slug)) {
        issues.push({ file, message: `product ${slug} is not in the catalog` });
      }
    }
  }

  const fixtures = join(root, repoLayout.fixturesDir);
  let fixtureCount = 0;

  // Image configs: valid ones must pass everything, invalid ones must fail the schema,
  // invalid-semantic ones must pass the schema and fail the extra rules.
  for (const path of listFiles(join(fixtures, 'image'), ['.yml'])) {
    const file = relativePath(root, path);
    const kind = basename(join(path, '..'));
    fixtureCount += 1;
    const data = readData(path);
    const schemaErrors = validateAgainst('image-config', data, root);
    const semantic = schemaErrors.length === 0 ? imageConfigProblems(data as ImageConfig) : [];
    if (kind === 'invalid' && schemaErrors.length === 0) {
      issues.push({ file, message: 'expected the schema to reject this config' });
    } else if (kind === 'invalid-semantic' && (schemaErrors.length > 0 || semantic.length === 0)) {
      issues.push({ file, message: 'expected the schema to accept and the image rules to reject' });
    } else if (kind === 'image') {
      issues.push(...[...schemaErrors, ...semantic].map((message) => ({ file, message })));
    }
  }

  fixtureCount += checkPublished(
    root,
    { advisories: join(fixtures, 'data/advisories'), api: join(fixtures, feedLayout.basePath) },
    join(fixtures, 'notes'),
    slugs,
    issues,
    false,
  );

  // Ingest output: data/advisories and data/api/v1 obey the same rules, with notes from notes/.
  const data = join(root, repoLayout.dataDir);
  const published = existsSync(data)
    ? checkPublished(
        root,
        { advisories: join(root, repoLayout.advisoriesDir), api: join(root, repoLayout.feedDir) },
        join(root, repoLayout.notesDir),
        slugs,
        issues,
        true,
      )
    : 0;

  return {
    issues,
    counts: {
      products: catalog.entries.length,
      notes: notes.notes.length,
      fixtures: fixtureCount,
      published,
    },
  };
}

/**
 * Checks one published tree (fixtures/ or data/): the advisory files and the v1 feed. Advisories
 * must name catalog products and carry the reviewed note; the manifest must list every product
 * file with its exact etag and count; product files must hold the same advisories. With
 * requireKevCheck (the ingest output), every advisory must have been looked up in CISA KEV, so a
 * published listed: false always means "checked, not listed". Returns the number of files read.
 */
function checkPublished(
  root: string,
  dirs: { advisories: string; api: string },
  notesDir: string,
  slugs: ReadonlySet<string>,
  issues: Issue[],
  requireKevCheck: boolean,
): number {
  let fixtureCount = 0;
  const load = (path: string, schema: DocumentSchema): unknown => {
    fixtureCount += 1;
    const file = relativePath(root, path);
    try {
      const data = readData(path);
      issues.push(...validateAgainst(schema, data, root).map((message) => ({ file, message })));
      return data;
    } catch (error) {
      issues.push({ file, message: String(error) });
      return undefined;
    }
  };

  // Advisories: each must name catalog products, and its note must match the note fixture.
  const advisories = new Map<string, Advisory>();
  for (const path of listFiles(dirs.advisories, ['.json'])) {
    const advisory = load(path, 'advisory') as Advisory | undefined;
    if (advisory === undefined) continue;
    const file = relativePath(root, path);
    if (advisory.id !== basename(path, '.json')) {
      issues.push({ file, message: `id ${advisory.id} must equal the file name` });
    }
    if (requireKevCheck && advisory.kev.checked !== true) {
      issues.push({
        file,
        message: 'kev.checked must be true: the KEV catalog was not read for it',
      });
    }
    for (const { product } of advisory.affected) {
      if (!slugs.has(product)) {
        issues.push({ file, message: `product ${product} is not in the catalog` });
      }
    }
    const notePath = join(notesDir, `${advisory.id}.md`);
    const entry = existsSync(notePath) ? readNote(notePath, root) : undefined;
    if (Array.isArray(entry)) {
      fixtureCount += 1;
      issues.push(...entry);
    } else {
      if (entry !== undefined) fixtureCount += 1;
      const expected = entry === undefined ? null : toFeedNote(entry.note, entry.body);
      if (!isDeepStrictEqual(advisory.note, expected)) {
        issues.push({ file, message: `note does not match ${relativePath(root, notePath)}` });
      }
    }
    advisories.set(advisory.id, advisory);
  }

  // Published feed: manifest entries and product files must agree byte for byte.
  const api = dirs.api;
  const manifestPath = join(api, feedLayout.manifest);
  const manifest = existsSync(manifestPath)
    ? (load(manifestPath, 'manifest') as Manifest | undefined)
    : undefined;
  const productFiles = listFiles(join(api, 'products'), ['.json']);
  for (const path of productFiles) {
    const feed = load(path, 'product-feed') as ProductFeed | undefined;
    if (feed === undefined) continue;
    const file = relativePath(root, path);
    const slug = basename(path, '.json');
    if (feed.product.slug !== slug) {
      issues.push({ file, message: `product.slug ${feed.product.slug} must equal the file name` });
    }
    const entry = manifest?.products[slug];
    if (entry === undefined) {
      issues.push({ file, message: 'missing from manifest.json' });
    } else {
      const etag = etagOf(readFileSync(path));
      if (entry.etag !== etag) {
        issues.push({
          file,
          message: `etag in manifest.json does not match the file bytes: ${etag}`,
        });
      }
      if (entry.advisories !== feed.advisories.length) {
        issues.push({ file, message: 'advisory count in manifest.json is wrong' });
      }
    }
    for (const advisory of feed.advisories) {
      if (!advisory.affected.some((affected) => affected.product === slug)) {
        issues.push({ file, message: `${advisory.id} does not affect ${slug}` });
      }
      const source = advisories.get(advisory.id);
      if (source !== undefined && !isDeepStrictEqual(source, advisory)) {
        issues.push({
          file,
          message: `${advisory.id} differs from ${relativePath(root, dirs.advisories)}`,
        });
      }
    }
  }
  for (const slug of Object.keys(manifest?.products ?? {})) {
    if (!productFiles.some((path) => basename(path, '.json') === slug)) {
      issues.push({
        file: relativePath(root, manifestPath),
        message: `lists ${slug} but products/${slug}.json is missing`,
      });
    }
  }
  return fixtureCount;
}

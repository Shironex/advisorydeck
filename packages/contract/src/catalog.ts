import { readFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { listFiles, parseYaml, relativePath } from './files.ts';
import type { Product } from './generated/types.ts';
import type { Issue } from './issues.ts';
import { repoLayout, repoRoot } from './layout.ts';
import { validateAgainst } from './schemas.ts';

export interface CatalogEntry {
  /** Repository-relative path of the YAML file. */
  file: string;
  product: Product;
}

export interface Catalog {
  entries: CatalogEntry[];
  issues: Issue[];
}

/** Loads catalog/<category>/<slug>.yml, validates each entry and the rules a schema cannot express. */
export function loadCatalog(root = repoRoot()): Catalog {
  const dir = join(root, repoLayout.catalogDir);
  const entries: CatalogEntry[] = [];
  const issues: Issue[] = [];
  const seen = new Map<string, string>();
  const today = new Date().toISOString().slice(0, 10);

  for (const path of listFiles(dir, ['.yml', '.yaml'])) {
    const file = relativePath(root, path);
    if (path.endsWith('.yaml')) {
      issues.push({ file, message: 'catalog files use the .yml extension' });
      continue;
    }
    let data: unknown;
    try {
      data = parseYaml(readFileSync(path, 'utf8'));
    } catch (error) {
      issues.push({ file, message: `YAML: ${String(error)}` });
      continue;
    }
    const errors = validateAgainst('product', data, root);
    if (errors.length > 0) {
      issues.push(...errors.map((message) => ({ file, message })));
      continue;
    }
    const product = data as Product;
    const before = issues.length;
    if (product.slug !== basename(path, '.yml')) {
      issues.push({ file, message: `slug ${product.slug} must equal the file name` });
    }
    if (product.category !== basename(dirname(path))) {
      issues.push({ file, message: `category ${product.category} must equal the folder name` });
    }
    const other = seen.get(product.slug);
    if (other !== undefined) {
      issues.push({ file, message: `slug ${product.slug} is already used by ${other}` });
    }
    seen.set(product.slug, file);
    for (const image of product.images) {
      try {
        if (!new RegExp(image.tag_pattern).source.includes('(?<version>')) {
          issues.push({ file, message: `tag_pattern of ${image.ref} has no version group` });
        }
      } catch (error) {
        issues.push({ file, message: `tag_pattern of ${image.ref}: ${String(error)}` });
      }
    }
    const since = product.upstream?.since;
    if (since !== undefined && since > today) {
      issues.push({ file, message: `upstream.since ${since} is in the future` });
    }
    if (issues.length === before) {
      entries.push({ file, product });
    }
  }
  if (entries.length === 0 && issues.length === 0) {
    issues.push({ file: repoLayout.catalogDir, message: 'the catalog is empty' });
  }
  return { entries, issues };
}

/** Matches an image tag against a catalog tag pattern and returns the version, or undefined. */
export function versionFromTag(tagPattern: string, tag: string): string | undefined {
  return new RegExp(tagPattern).exec(tag)?.groups?.['version'];
}

import { readdirSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { parseDocument } from 'yaml';

/** Files (never directories) under dir whose name ends with one of the extensions, sorted, as absolute paths. */
export function listFiles(dir: string, extensions: readonly string[]): string[] {
  let names: string[];
  try {
    names = readdirSync(dir, { recursive: true, encoding: 'utf8' });
  } catch {
    return [];
  }
  return names
    .map((name) => join(dir, name))
    .filter((path) => extensions.some((ext) => path.endsWith(ext)) && statSync(path).isFile())
    .sort();
}

/** Repository-relative path with forward slashes on every OS. */
export function relativePath(root: string, path: string): string {
  return relative(root, path).split(sep).join('/');
}

/** Parses YAML strictly (duplicate keys and syntax errors throw). */
export function parseYaml(text: string): unknown {
  const doc = parseDocument(text, { uniqueKeys: true, prettyErrors: true });
  const first = doc.errors[0];
  if (first !== undefined) {
    throw first;
  }
  return doc.toJS() as unknown;
}

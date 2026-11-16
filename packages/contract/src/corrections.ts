import { readFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { listFiles, parseYaml, relativePath } from './files.ts';
import type { Correction } from './generated/types.ts';
import type { Issue } from './issues.ts';
import { repoLayout, repoRoot } from './layout.ts';
import { validateAgainst } from './schemas.ts';

export interface CorrectionEntry {
  /** Repository-relative path of the YAML file. */
  file: string;
  correction: Correction;
}

/**
 * Loads corrections/<product>/<advisory-id>.yml and validates each file: the schema, the file
 * name (the advisory id) and the folder (the product).
 */
export function loadCorrections(root = repoRoot()): {
  corrections: CorrectionEntry[];
  issues: Issue[];
} {
  const corrections: CorrectionEntry[] = [];
  const issues: Issue[] = [];
  for (const path of listFiles(join(root, repoLayout.correctionsDir), ['.yml', '.yaml'])) {
    const file = relativePath(root, path);
    if (path.endsWith('.yaml')) {
      issues.push({ file, message: 'correction files use the .yml extension' });
      continue;
    }
    let data: unknown;
    try {
      data = parseYaml(readFileSync(path, 'utf8'));
    } catch (error) {
      issues.push({ file, message: `YAML: ${String(error)}` });
      continue;
    }
    const errors = validateAgainst('correction', data, root);
    if (errors.length > 0) {
      issues.push(...errors.map((message) => ({ file, message })));
      continue;
    }
    const correction = data as Correction;
    const before = issues.length;
    if (correction.advisory !== basename(path, '.yml')) {
      issues.push({ file, message: `advisory ${correction.advisory} must equal the file name` });
    }
    if (correction.product !== basename(dirname(path))) {
      issues.push({ file, message: `product ${correction.product} must equal the folder name` });
    }
    if (issues.length === before) corrections.push({ file, correction });
  }
  return { corrections, issues };
}

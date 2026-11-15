import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { checkRepository, repoRoot, validateAgainst } from '../src/index.ts';

const root = repoRoot();
const advisoryPath = 'fixtures/data/advisories/CVE-2026-120154.json';
const feedPath = 'fixtures/api/v1/products/postgresql.json';

function readJson(path: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(root, path), 'utf8')) as Record<string, unknown>;
}

let scratch: string | undefined;

/** A throwaway copy of the data folders, to mutate. */
function copyRepo(): string {
  scratch = mkdtempSync(join(tmpdir(), 'advisorydeck-'));
  for (const dir of ['catalog', 'schemas', 'fixtures', 'notes']) {
    cpSync(join(root, dir), join(scratch, dir), { recursive: true });
  }
  return scratch;
}

afterEach(() => {
  if (scratch !== undefined) rmSync(scratch, { recursive: true, force: true });
  scratch = undefined;
});

describe('repository data', () => {
  it('has no problems', () => {
    const report = checkRepository();
    expect(report.issues).toEqual([]);
    expect(report.counts.products).toBe(5);
  });

  it('notices a product file that no longer matches its manifest etag', () => {
    const copy = copyRepo();
    const path = join(copy, feedPath);
    writeFileSync(path, readFileSync(path, 'utf8').replace('"18.7"', '"18.8"'));
    const messages = checkRepository(copy).issues.map((issue) => issue.message);
    expect(messages.some((m) => m.startsWith('etag in manifest.json does not match'))).toBe(true);
  });

  it('notices a catalog entry in the wrong folder', () => {
    const copy = copyRepo();
    cpSync(join(copy, 'catalog/databases/redis.yml'), join(copy, 'catalog/proxies/redis.yml'));
    const messages = checkRepository(copy).issues.map((issue) => issue.message);
    expect(messages).toContain('category databases must equal the folder name');
    expect(messages.some((message) => message.startsWith('slug redis is already used'))).toBe(true);
  });

  it('notices a feed note that drifted from its note file', () => {
    const copy = copyRepo();
    const path = join(copy, 'fixtures/notes/CVE-2026-120154.md');
    writeFileSync(path, readFileSync(path, 'utf8').replace('status: reviewed', 'status: draft'));
    const messages = checkRepository(copy).issues.map((issue) => issue.message);
    expect(messages).toContain('note does not match fixtures/notes/CVE-2026-120154.md');
  });
});

describe('schema rules', () => {
  const advisory = readJson(advisoryPath);

  it('rejects a range with both fixed and last_affected', () => {
    const broken = structuredClone(advisory);
    broken['affected'] = [
      {
        product: 'postgresql',
        ranges: [{ introduced: '17', fixed: '17.12', last_affected: '17.11' }],
      },
    ];
    expect(validateAgainst('advisory', broken)).not.toEqual([]);
  });

  it('accepts unknown ranges as an empty list', () => {
    const unknown = structuredClone(advisory);
    unknown['affected'] = [{ product: 'postgresql', ranges: [] }];
    expect(validateAgainst('advisory', unknown)).toEqual([]);
  });

  it('rejects a published note that is not reviewed', () => {
    const broken = structuredClone(advisory);
    (broken['note'] as Record<string, unknown>)['status'] = 'draft';
    expect(validateAgainst('advisory', broken)).not.toEqual([]);
  });

  const note = {
    advisory: 'CVE-2026-120154',
    products: ['postgresql'],
    audience: 'generic-selfhosters',
    exposure: 'not-default',
    assumptions: ['No row security policies are used.'],
    actions: [{ kind: 'backup' }],
    status: 'draft',
    authorship: 'model-drafted',
  };

  it('accepts a model-drafted draft', () => {
    expect(validateAgainst('curated-note', note)).toEqual([]);
  });

  it('requires a reviewer and date on a reviewed note', () => {
    expect(
      validateAgainst('curated-note', { ...note, status: 'reviewed', authorship: 'human' }),
    ).not.toEqual([]);
  });

  it('never marks unreviewed model text as reviewed', () => {
    const reviewed = {
      ...note,
      status: 'reviewed',
      reviewed_by: 'someone',
      reviewed_at: '2026-11-13',
    };
    expect(validateAgainst('curated-note', reviewed)).not.toEqual([]);
    expect(validateAgainst('curated-note', { ...reviewed, authorship: 'human' })).toEqual([]);
  });

  it('requires assumptions next to a not-default exposure', () => {
    expect(validateAgainst('curated-note', { ...note, assumptions: [] })).not.toEqual([]);
    expect(
      validateAgainst('curated-note', { ...note, exposure: 'unknown', assumptions: [] }),
    ).toEqual([]);
  });

  it('requires code on a commands action', () => {
    expect(
      validateAgainst('curated-note', { ...note, actions: [{ kind: 'commands' }] }),
    ).not.toEqual([]);
  });
});

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Ajv2020, type ErrorObject, type ValidateFunction } from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { repoLayout, repoRoot, SCHEMA_BASE } from './layout.ts';

export const SCHEMA_NAMES = [
  'defs',
  'product',
  'advisory',
  'product-feed',
  'manifest',
  'image-config',
  'curated-note',
] as const;

export type SchemaName = (typeof SCHEMA_NAMES)[number];

/** Schemas a document can be validated against (defs only holds shared pieces). */
export type DocumentSchema = Exclude<SchemaName, 'defs'>;

export function schemaId(name: SchemaName): string {
  return `${SCHEMA_BASE}/${name}.schema.json`;
}

export function readSchema(name: SchemaName, root = repoRoot()): Record<string, unknown> {
  const path = join(root, repoLayout.schemasDir, `${name}.schema.json`);
  return JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>;
}

function createAjv(root: string): Ajv2020 {
  const ajv = new Ajv2020({
    allErrors: true,
    strict: true,
    strictTypes: false,
    strictRequired: false,
  });
  addFormats.default(ajv);
  for (const name of SCHEMA_NAMES) {
    ajv.addSchema(readSchema(name, root));
  }
  return ajv;
}

let cached: { root: string; ajv: Ajv2020 } | undefined;

function ajvFor(root: string): Ajv2020 {
  if (cached?.root !== root) {
    cached = { root, ajv: createAjv(root) };
  }
  return cached.ajv;
}

function describe(error: ErrorObject): string {
  const where = error.instancePath === '' ? '(root)' : error.instancePath;
  const extra =
    error.keyword === 'additionalProperties'
      ? ` (${String((error.params as { additionalProperty?: string }).additionalProperty)})`
      : error.keyword === 'enum'
        ? ` (${(error.params as { allowedValues: unknown[] }).allowedValues.join(', ')})`
        : '';
  return `${where} ${error.message ?? 'is invalid'}${extra}`;
}

/** Validates data against one schema and returns readable messages; empty means valid. */
export function validateAgainst(name: DocumentSchema, data: unknown, root = repoRoot()): string[] {
  const validate: ValidateFunction | undefined = ajvFor(root).getSchema(schemaId(name));
  if (validate === undefined) {
    throw new Error(`schema ${name} is not loaded`);
  }
  if (validate(data)) {
    return [];
  }
  return (validate.errors ?? []).map(describe);
}

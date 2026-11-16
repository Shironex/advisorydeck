// Generates src/generated/types.ts from the JSON Schemas in schemas/v1. Run: pnpm gen:types
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { compile, type JSONSchema } from 'json-schema-to-typescript';
import { repoLayout, repoRoot, SCHEMA_BASE } from '../src/layout.ts';
import { schemaId } from '../src/schemas.ts';

const root = repoRoot();
const schemasDir = join(root, repoLayout.schemasDir);
const outFile = join(root, 'packages/contract/src/generated/types.ts');

// One wrapper schema so every named type is emitted exactly once.
const wrapper = {
  title: 'Schemas',
  type: 'object',
  additionalProperties: false,
  properties: {
    product: { $ref: schemaId('product') },
    advisory: { $ref: schemaId('advisory') },
    productFeed: { $ref: schemaId('product-feed') },
    manifest: { $ref: schemaId('manifest') },
    imageConfig: { $ref: schemaId('image-config') },
    curatedNote: { $ref: schemaId('curated-note') },
    correction: { $ref: schemaId('correction') },
  },
} as unknown as JSONSchema;

// Resolve schema ids from disk instead of fetching them.
const localResolver = {
  order: 1,
  canRead: (file: { url: string }) => file.url.startsWith(`${SCHEMA_BASE}/`),
  read: (file: { url: string }) =>
    readFileSync(
      join(schemasDir, file.url.slice(SCHEMA_BASE.length + 1).split('#')[0] ?? ''),
      'utf8',
    ),
};

const output = await compile(wrapper, 'Schemas', {
  bannerComment:
    '/* Generated from schemas/v1 by packages/contract/scripts/gen-types.ts. Do not edit; run pnpm gen:types. */',
  additionalProperties: false,
  unreachableDefinitions: false,
  strictIndexSignatures: true,
  style: { singleQuote: true, printWidth: 100 },
  $refOptions: { resolve: { local: localResolver, http: false } },
});

writeFileSync(outFile, output);
console.log(`wrote ${outFile.slice(root.length + 1)}`);

import { writeFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { loadCatalog } from '@advisorydeck/contract';
import { Http } from './http.ts';
import {
  analyze,
  coolifyTemplates,
  dokployTemplate,
  renderReport,
  zipCommit,
  type CatalogImage,
  type TemplateInput,
} from './suggest.ts';
import { readZipBuffer } from './zip.ts';

const usage = `pnpm catalog:suggest [--out <file>]

Reads the Coolify service templates and the Dokploy blueprints, diffs their images against the
catalog and writes one markdown issue body (stdout without --out). It never writes catalog files.`;

const COOLIFY_BRANCH = 'main';
const COOLIFY_URL = `https://raw.githubusercontent.com/coollabsio/coolify/${COOLIFY_BRANCH}/templates/service-templates-latest.json`;
const DOKPLOY_BRANCH = 'canary';
const DOKPLOY_URL = `https://codeload.github.com/Dokploy/templates/zip/refs/heads/${DOKPLOY_BRANCH}`;

const { values } = parseArgs({
  options: { out: { type: 'string' }, help: { type: 'boolean', default: false } },
});
if (values.help) {
  console.log(usage);
  process.exit(0);
}

const log = (message: string) => {
  console.error(message);
};
const http = new Http({ log });

async function download(url: string): Promise<Response> {
  const response = await http.request(url);
  if (response === undefined) throw new Error(`not found: ${url}`);
  return response;
}

log(`downloading Coolify templates (${COOLIFY_BRANCH})`);
const coolify = coolifyTemplates(await (await download(COOLIFY_URL)).json());

log(`downloading Dokploy templates (${DOKPLOY_BRANCH})`);
const zip = Buffer.from(await (await download(DOKPLOY_URL)).arrayBuffer());
const blueprints = new Map<string, { compose?: string; meta?: string }>();
await readZipBuffer(
  zip,
  (name) => /^[^/]+\/blueprints\/[^/]+\/(docker-compose\.yml|meta\.json)$/.test(name),
  (name, data) => {
    const [, , id, file] = name.split('/');
    if (id === undefined) return;
    const slot = blueprints.get(id) ?? {};
    if (file === 'meta.json') slot.meta = data.toString('utf8');
    else slot.compose = data.toString('utf8');
    blueprints.set(id, slot);
  },
);
const dokploy: TemplateInput[] = [];
for (const id of [...blueprints.keys()].sort()) {
  const slot = blueprints.get(id);
  if (slot?.compose !== undefined) dokploy.push(dokployTemplate(id, slot.compose, slot.meta));
}

const catalog = loadCatalog();
if (catalog.issues.length > 0) {
  throw new Error(`the catalog has ${String(catalog.issues.length)} issues; run pnpm validate`);
}
const images: CatalogImage[] = catalog.entries.flatMap((entry) =>
  entry.product.images.map((image) => ({
    slug: entry.product.slug,
    ref: image.ref.toLowerCase(),
    tagPattern: image.tag_pattern,
  })),
);

const commit = zipCommit(zip);
const markdown = renderReport(analyze([...coolify, ...dokploy], images), [
  { label: 'Coolify source', detail: `coollabsio/coolify, branch ${COOLIFY_BRANCH}` },
  {
    label: 'Dokploy source',
    detail: `Dokploy/templates, branch ${DOKPLOY_BRANCH}${commit === undefined ? '' : `, commit ${commit}`}`,
  },
]);
if (values.out === undefined) process.stdout.write(markdown);
else {
  writeFileSync(values.out, markdown);
  log(`wrote ${values.out}`);
}

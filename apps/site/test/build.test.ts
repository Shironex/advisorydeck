/**
 * Builds the site once against a copy of the repository data with one note in each state, then
 * checks the output: every product, category and advisory page, the Atom feeds, the note states,
 * and the published api/v1 files byte for byte.
 */
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  cpSync,
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadCatalog, repoRoot, type Manifest } from '@advisorydeck/contract';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

const repo = repoRoot();
const siteDir = fileURLToPath(new URL('..', import.meta.url));
let work: string;
let dist: string;

const advisoryIds = readdirSync(join(repo, 'data/advisories'))
  .filter((f) => f.endsWith('.json'))
  .map((f) => f.slice(0, -'.json'.length));
const products = loadCatalog(repo).entries.map((e) => e.product);

// Four real PostgreSQL advisories get a note each; a fifth stays without one.
const pg = JSON.parse(readFileSync(join(repo, 'data/api/v1/products/postgresql.json'), 'utf8')) as {
  advisories: { id: string }[];
};
const [draftId, reviewedId, disputedId, supersededId, noneId] = pg.advisories.map((a) => a.id) as [
  string,
  string,
  string,
  string,
  string,
];

function note(id: string, status: string, extra: string): string {
  return `---
advisory: ${id}
products: [postgresql]
audience: generic-selfhosters
exposure: not-default
assumptions:
  - Port 5432 is not published outside the Docker network.
actions:
  - kind: backup
  - kind: commands
    code: |
      docker compose pull
      docker compose up -d
status: ${status}
authorship: human
written_by: example-author
${extra}---

Test note body for ${status} with <b>markup</b> that must stay text.
`;
}

function page(path: string): string {
  return readFileSync(join(dist, path), 'utf8');
}

beforeAll(() => {
  work = mkdtempSync(join(tmpdir(), 'advisorydeck-site-'));
  const root = join(work, 'root');
  dist = join(work, 'dist');
  for (const dir of ['catalog', 'data', 'schemas', 'notes']) {
    cpSync(join(repo, dir), join(root, dir), { recursive: true });
  }
  // A fixture product marked archived upstream in the copied catalog.
  const traefik = join(root, 'catalog/proxies/traefik.yml');
  writeFileSync(
    traefik,
    `${readFileSync(traefik, 'utf8')}upstream:\n  status: archived\n  since: 2026-10-01\n  note: Moved to example-fork.\n`,
  );
  writeFileSync(join(root, 'notes', `${draftId}.md`), note(draftId, 'draft', ''));
  writeFileSync(
    join(root, 'notes', `${reviewedId}.md`),
    note(reviewedId, 'reviewed', 'reviewed_by: example-reviewer\nreviewed_at: 2026-11-13\n'),
  );
  writeFileSync(join(root, 'notes', `${disputedId}.md`), note(disputedId, 'disputed', ''));
  writeFileSync(join(root, 'notes', `${supersededId}.md`), note(supersededId, 'superseded', ''));
  // Vitest puts Vite's own variables (BASE_URL, MODE ...) into process.env; a child build would
  // read BASE_URL from there and lose the site's base path.
  const env = Object.fromEntries(
    Object.entries(process.env).filter(
      ([key]) =>
        !['BASE_URL', 'MODE', 'DEV', 'PROD', 'SSR', 'NODE_ENV'].includes(key) &&
        !key.startsWith('VITEST'),
    ),
  );
  execFileSync(join(siteDir, 'node_modules/.bin/astro'), ['build', '--outDir', dist], {
    cwd: siteDir,
    env: { ...env, ADVISORYDECK_ROOT: root, ASTRO_TELEMETRY_DISABLED: '1' },
    stdio: 'pipe',
  });
});

afterAll(() => {
  rmSync(work, { recursive: true, force: true });
});

describe('site build', () => {
  it('renders a page and an Atom feed for every product', () => {
    expect(products.length).toBeGreaterThan(0);
    for (const product of products) {
      const html = page(`products/${product.slug}/index.html`);
      expect(html, product.slug).toMatch(new RegExp(`<h1[^>]*>${product.name}</h1>`));
      expect(html).toContain(`products/${product.slug}/feed.xml`);
      const atom = page(`products/${product.slug}/feed.xml`);
      expect(atom).toContain('<feed xmlns="http://www.w3.org/2005/Atom">');
    }
  });

  it('shows an archived upstream notice with text and an icon on the product page', () => {
    const html = page('products/traefik/index.html');
    const notice =
      /<div class="notice notice--warn" role="note" data-upstream="archived">([\s\S]*?)<\/div>\s*<\/div>/.exec(
        html,
      )?.[1];
    expect(notice).toBeDefined();
    expect(notice).toContain('<svg');
    expect(notice).toContain('Archived upstream since 1 Oct 2026: Moved to example-fork.');
    expect(page('products/postgresql/index.html')).not.toContain('data-upstream');
  });

  it('renders a page for every advisory', () => {
    expect(advisoryIds.length).toBeGreaterThan(0);
    for (const id of advisoryIds) {
      const html = page(`advisories/${id}/index.html`);
      expect(html, id).toContain(`<span class="mono meta-id">${id}</span>`);
      expect(html, id).toContain('Affected versions and the fix');
    }
  });

  it('renders every category in use, the index pages and the sources page', () => {
    for (const category of new Set(products.map((p) => p.category))) {
      expect(existsSync(join(dist, `categories/${category}/index.html`)), category).toBe(true);
    }
    for (const path of [
      'index.html',
      'products/index.html',
      'advisories/index.html',
      'sources/index.html',
      'generator/index.html',
      '404.html',
    ]) {
      expect(existsSync(join(dist, path)), path).toBe(true);
    }
    expect(page('sources/index.html')).toContain('CVE Program Terms of Use');
  });

  it('prefixes internal links with the base path', () => {
    const html = page('index.html');
    expect(html).toContain('href="/advisorydeck/products/"');
    expect(html).not.toMatch(/href="\/(products|advisories|generator|sources)\//);
  });

  it('publishes the overall Atom feed with absolute links under the base path', () => {
    const atom = page('feed.xml');
    expect(atom).toContain(
      '<link rel="self" type="application/atom+xml" href="https://shironex.github.io/advisorydeck/feed.xml"/>',
    );
    expect(atom.match(/<entry>/g)?.length).toBe(Math.min(50, advisoryIds.length));
  });

  it('copies api/v1 byte for byte, so every manifest etag still matches', () => {
    const source = join(repo, 'data/api/v1');
    const manifestBytes = readFileSync(join(dist, 'api/v1/manifest.json'));
    expect(manifestBytes.equals(readFileSync(join(source, 'manifest.json')))).toBe(true);
    const manifest = JSON.parse(manifestBytes.toString('utf8')) as Manifest;
    for (const [slug, entry] of Object.entries(manifest.products)) {
      const bytes = readFileSync(join(dist, `api/v1/products/${slug}.json`));
      expect(bytes.equals(readFileSync(join(source, `products/${slug}.json`))), slug).toBe(true);
      expect(`sha256:${createHash('sha256').update(bytes).digest('hex')}`, slug).toBe(entry?.etag);
    }
  });

  it('shows the KEV state and the EPSS score with its date from the feed', () => {
    const advisory = JSON.parse(
      readFileSync(join(repo, `data/advisories/${noneId}.json`), 'utf8'),
    ) as { kev: { listed: boolean; checked?: boolean }; epss: { date: string } | null };
    const html = page(`advisories/${noneId}/index.html`);
    const expected = advisory.kev.listed
      ? 'Yes, listed in CISA KEV'
      : advisory.kev.checked === true
        ? 'Not listed in CISA KEV'
        : 'Not checked against CISA KEV yet';
    expect(html).toContain(expected);
    if (advisory.epss !== null) {
      expect(html).toContain(`scored ${advisory.epss.date}`);
    }
  });

  it('lists every upstream source and its terms on the sources page', () => {
    const html = page('sources/index.html');
    for (const code of ['CVE-TOU', 'CC-BY-4.0', 'MIT', 'CC0-1.0', 'FIRST-EPSS', 'NVD-TOU']) {
      expect(html, code).toContain(code);
    }
    expect(html).toContain('EPSS scores are provided by FIRST.org, Inc.');
    expect(html).toContain('not endorsed or certified by the NVD');
  });
});

describe('curated note states', () => {
  it('none: says there is no reviewed note and offers to request one', () => {
    const html = page(`advisories/${noneId}/index.html`);
    expect(html).toContain('data-state="none"');
    expect(html).toContain('No reviewed note for this advisory yet');
    expect(html).toContain('template=curated-note.yml');
  });

  it('draft: clearly labelled, never presented as reviewed', () => {
    const html = page(`advisories/${draftId}/index.html`);
    expect(html).toContain('data-state="draft"');
    expect(html).toContain('Unreviewed draft: do not rely on it');
    expect(html).toContain('Draft, not reviewed');
    expect(html).not.toContain('tag--reviewed');
  });

  it('reviewed: reviewer, date, and the exposure label next to its assumptions', () => {
    const html = page(`advisories/${reviewedId}/index.html`);
    expect(html).toContain('data-state="reviewed"');
    expect(html).toContain('by example-reviewer');
    expect(html).toMatch(/<time datetime="2026-11-13"[^>]*>13 Nov 2026<\/time>/);
    const label = html.indexOf('Not exposed on a default setup');
    const assumption = html.indexOf('Port 5432 is not published outside the Docker network.');
    expect(label).toBeGreaterThan(-1);
    expect(assumption).toBeGreaterThan(label);
    expect(html.slice(label, assumption)).toContain('Assumes, all of these true for you');
    expect(html).toContain('template=wrong-note.yml');
  });

  it('disputed: hides the exposure label and shows the banner', () => {
    const html = page(`advisories/${disputedId}/index.html`);
    expect(html).toContain('data-state="disputed"');
    expect(html).not.toContain('Not exposed on a default setup');
    expect(html).toContain('Someone reported this note as wrong');
  });

  it('superseded: kept as history', () => {
    expect(page(`advisories/${supersededId}/index.html`)).toContain('Kept for history');
  });

  it('escapes markup in note bodies', () => {
    const html = page(`advisories/${draftId}/index.html`);
    expect(html).toContain('&lt;b&gt;markup&lt;/b&gt;');
    expect(html).not.toContain('<b>markup</b>');
  });
});

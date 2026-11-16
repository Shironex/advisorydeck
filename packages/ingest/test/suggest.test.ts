import { describe, expect, it } from 'vitest';
import {
  analyze,
  coolifyTemplates,
  dokployTemplate,
  extractImages,
  githubRepo,
  normalizeImage,
  renderReport,
  zipCommit,
  type CatalogImage,
  type TemplateInput,
} from '../src/suggest.ts';

describe('normalizeImage', () => {
  it('fully qualifies Docker Hub references', () => {
    expect(normalizeImage('postgres:16')).toEqual({
      kind: 'image',
      ref: 'docker.io/library/postgres',
      tag: '16',
      floating: false,
    });
    expect(normalizeImage('n8nio/n8n:1.104.0')).toMatchObject({ ref: 'docker.io/n8nio/n8n' });
    expect(normalizeImage('docker.io/redis:7')).toMatchObject({ ref: 'docker.io/library/redis' });
  });

  it('keeps other registries and lowercases the name but not the tag', () => {
    expect(normalizeImage('GHCR.io/Owner/App:RELEASE.2025-01-01')).toEqual({
      kind: 'image',
      ref: 'ghcr.io/owner/app',
      tag: 'RELEASE.2025-01-01',
      floating: false,
    });
    expect(normalizeImage('quay.io/org/app:2.1')).toMatchObject({ ref: 'quay.io/org/app' });
    expect(normalizeImage('localhost:5000/team/app:1.0')).toMatchObject({
      ref: 'localhost:5000/team/app',
      tag: '1.0',
    });
  });

  it('maps a vendor mirror to the catalog name', () => {
    expect(normalizeImage('docker.n8n.io/n8nio/n8n:1.104.0')).toMatchObject({
      ref: 'docker.io/n8nio/n8n',
    });
  });

  it('drops a digest and strips quotes', () => {
    expect(normalizeImage(`'ghcr.io/o/a:1.2.3@sha256:${'a'.repeat(64)}'`)).toMatchObject({
      ref: 'ghcr.io/o/a',
      tag: '1.2.3',
    });
    expect(normalizeImage(`ghcr.io/o/a@sha256:${'a'.repeat(64)}`)).toMatchObject({
      tag: undefined,
      floating: true,
    });
  });

  it('uses the default of a variable and a placeholder otherwise', () => {
    expect(normalizeImage('${IMG:-nginx:1.27}')).toMatchObject({
      ref: 'docker.io/library/nginx',
      tag: '1.27',
    });
    expect(normalizeImage('app/web:${VERSION}')).toMatchObject({ tag: '<var>', floating: true });
    expect(normalizeImage('app/web:${VERSION:-2.0}')).toMatchObject({
      tag: '2.0',
      floating: false,
    });
  });

  it('skips an image that is entirely a variable', () => {
    expect(normalizeImage('${IMAGE}')).toEqual({ kind: 'variable' });
    expect(normalizeImage('$IMAGE:1')).toEqual({ kind: 'variable' });
    expect(normalizeImage('${REGISTRY}/app:1')).toEqual({ kind: 'variable' });
  });

  it('detects floating tags', () => {
    for (const tag of ['latest', 'main', 'stable', 'Edge', 'nightly', 'lts']) {
      expect(normalizeImage(`o/a:${tag}`)).toMatchObject({ floating: true });
    }
    expect(normalizeImage('o/a')).toMatchObject({ floating: true, tag: undefined });
    expect(normalizeImage('o/a:v1.2.3')).toMatchObject({ floating: false });
  });

  it('denies helper images', () => {
    expect(normalizeImage('busybox')).toEqual({ kind: 'denied', ref: 'docker.io/library/busybox' });
    expect(normalizeImage('alpine:3.20')).toMatchObject({ kind: 'denied' });
    expect(normalizeImage('x')).toMatchObject({ kind: 'denied' });
    expect(normalizeImage('curlimages/curl:8.5.0')).toMatchObject({ kind: 'denied' });
  });
});

describe('extractImages', () => {
  it('reads image lines from a compose file and ignores comments', () => {
    const compose = [
      'services:',
      '  web:',
      "    image: 'ghcr.io/o/web:1.0' # pinned",
      '  db:',
      '    image: postgres:16',
      '  # image: old/thing:1',
      '    environment:',
      '      - IMAGE_NAME=not/an:image',
      '',
    ].join('\n');
    expect(extractImages(compose)).toEqual(["'ghcr.io/o/web:1.0'", 'postgres:16']);
  });
});

describe('sources', () => {
  it('accepts only plain GitHub repository URLs', () => {
    expect(githubRepo('https://github.com/n8n-io/n8n')).toBe('n8n-io/n8n');
    expect(githubRepo('https://github.com/o/r.git')).toBe('o/r');
    expect(githubRepo('https://github.com/o/r?utm_source=coolify.io')).toBeUndefined();
    expect(githubRepo('https://evil.example/o/r')).toBeUndefined();
    expect(githubRepo(42)).toBeUndefined();
  });

  it('decodes Coolify compose and sorts by name', () => {
    const compose = Buffer.from('services:\n  a:\n    image: o/a:1.0\n').toString('base64');
    const templates = coolifyTemplates({
      zed: { compose, documentation: 'https://github.com/o/a' },
      alpha: { compose },
      broken: { slogan: 'no compose' },
    });
    expect(templates.map((t) => t.name)).toEqual(['alpha', 'zed']);
    expect(extractImages(templates[1]?.compose ?? '')).toEqual(['o/a:1.0']);
    expect(templates[1]?.github).toBe('o/a');
  });

  it('survives bad meta JSON', () => {
    expect(dokployTemplate('x', 'image: a/b:1', '{nope').github).toBeUndefined();
    expect(
      dokployTemplate('x', 'image: a/b:1', '{"links":{"github":"https://github.com/a/b"}}'),
    ).toMatchObject({
      github: 'a/b',
      source: 'dokploy',
    });
  });

  it('reads the commit SHA from the zip comment', () => {
    const sha = 'a'.repeat(40);
    const end = Buffer.alloc(22);
    end.writeUInt32LE(0x06054b50, 0);
    end.writeUInt16LE(40, 20);
    expect(zipCommit(Buffer.concat([Buffer.from('xx'), end, Buffer.from(sha)]))).toBe(sha);
    expect(zipCommit(Buffer.from('not a zip'))).toBeUndefined();
  });
});

const catalog: CatalogImage[] = [
  {
    slug: 'postgresql',
    ref: 'docker.io/library/postgres',
    tagPattern: '^(?<version>[0-9]+(?:\\.[0-9]+)?)(?:-[a-z].*)?$',
  },
  { slug: 'unused', ref: 'ghcr.io/o/unused', tagPattern: '^(?<version>[0-9.]+)$' },
];

function template(
  source: TemplateInput['source'],
  name: string,
  compose: string,
  github?: string,
): TemplateInput {
  return { source, name, compose, github };
}

const templates: TemplateInput[] = [
  template('coolify', 'app-a', 'image: postgres:16\nimage: o/web:1.0\nimage: busybox\n', 'o/web'),
  template('coolify', 'app-b', 'image: o/web:1.1\nimage: ${DB}\nimage: o/rare:latest'),
  template('dokploy', 'web', 'image: o/web:1.2\nimage: postgres:bookworm', 'o/web'),
  template('dokploy', 'solo', 'image: o/solo:3.0', 'o/solo-repo'),
];

describe('analyze', () => {
  const report = analyze(templates, catalog);

  it('ranks unmatched images by template count', () => {
    expect(report.candidates.map((c) => c.ref)).toEqual([
      'docker.io/o/web',
      'docker.io/o/rare',
      'docker.io/o/solo',
    ]);
    expect(report.candidates[0]).toMatchObject({
      coolify: ['app-a', 'app-b'],
      dokploy: ['web'],
      pinnedTags: ['1.0', '1.1', '1.2'],
      upstream: ['o/web'],
    });
    expect(report.candidates[2]?.upstream).toEqual(['o/solo-repo']);
  });

  it('reports a tag pattern that fails on a pinned tag, and unused catalog images', () => {
    expect(report.mismatches).toEqual([]);
    expect(report.unused).toEqual([{ slug: 'unused', ref: 'ghcr.io/o/unused' }]);
  });

  it('flags a pinned tag the pattern rejects', () => {
    const odd = analyze([template('coolify', 't', 'image: postgres:pg16-custom')], catalog);
    expect(odd.mismatches).toEqual([
      expect.objectContaining({ slug: 'postgresql', tags: ['pg16-custom'] }),
    ]);
  });

  it('counts stats', () => {
    expect(report.stats).toMatchObject({
      coolifyTemplates: 2,
      dokployTemplates: 2,
      variableSkipped: 1,
      deniedSkipped: 1,
      distinctImages: 4,
      occurrences: 7,
      floatingOccurrences: 2,
    });
  });
});

describe('renderReport', () => {
  const sources = [{ label: 'Coolify source', detail: 'o/c, branch main' }];

  it('is stable and independent of input order', () => {
    const a = renderReport(analyze(templates, catalog), sources);
    const b = renderReport(analyze([...templates].reverse(), [...catalog].reverse()), sources);
    expect(a).toBe(b);
    expect(a).toContain('| `docker.io/o/web` | 2 | 1 |');
    expect(a).toContain('## Catalog images no template uses');
    expect(a).toMatch(/Templates read: 2 Coolify, 2 Dokploy/);
    expect(a).not.toMatch(/[\u2013\u2014]/);
  });

  it('caps the table and says how many more exist', () => {
    const many = Array.from({ length: 5 }, (_, i) =>
      template('coolify', `t${String(i)}`, `image: o/a${String(i)}:1.0`),
    );
    const text = renderReport(analyze(many, []), sources, { top: 2 });
    expect(text).toContain('Showing the top 2 of 5 unmatched images; 3 more are not listed.');
    expect(text.match(/^\| `docker\.io/gm)).toHaveLength(2);
  });

  it('keeps untrusted text out of the markup', () => {
    const evil = template('coolify', 'x|@user <script>`', 'image: o/a:1.0');
    const text = renderReport(analyze([evil], []), sources);
    expect(text).not.toContain('@user');
    expect(text).not.toContain('<script>');
    expect(text).not.toContain('x|');
  });
});

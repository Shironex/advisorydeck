import { cpSync, mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import {
  etagOf,
  loadCatalog,
  repoRoot,
  validateAgainst,
  type Advisory,
  type Manifest,
  type ProductFeed,
} from '@advisorydeck/contract';
import { afterEach, describe, expect, it } from 'vitest';
import { EPSS_API, KEV_URLS } from '../src/enrich.ts';
import { ghsaQueries } from '../src/ghsa.ts';
import { Http, type FetchLike } from '../src/http.ts';
import { runIngest, type RunOptions } from '../src/run.ts';

const fixtures = join(repoRoot(), 'packages/ingest/test/fixtures');
const API = 'https://api.github.com';
const RELEASES = 'https://github.com/CVEProject/cvelistV5/releases/download';
const repoQuery = (repo: string) =>
  `${API}/repos/${repo}/security-advisories?state=published&sort=updated&direction=desc&per_page=100`;
// Global advisories are read with one query per ecosystem for every package the catalog names.
const globalQueries = ghsaQueries(loadCatalog().entries).filter((q) => q.kind === 'global');

interface Route {
  file?: string;
  body?: string;
  status?: number;
  headers?: Record<string, string>;
}

/** Recorded responses; anything else is a 404, so no test ever reaches the network. */
function routes(): Map<string, Route> {
  const page2 = `${repoQuery('coollabsio/coolify')}&after=cursor2`;
  return new Map<string, Route>([
    [`${API}/repos/CVEProject/cvelistV5/releases?per_page=100`, { file: 'cvelist/releases.json' }],
    [
      `${RELEASES}/cve_2026-11-14_at_end_of_day/2026-11-14_delta_CVEs_at_end_of_day.zip`,
      { file: 'cvelist/2026-11-14_delta_CVEs_at_end_of_day.zip' },
    ],
    [
      `${RELEASES}/cve_2026-11-15_0100Z/2026-11-15_delta_CVEs_at_0100Z.zip`,
      { file: 'cvelist/2026-11-15_delta_CVEs_at_0100Z.zip' },
    ],
    [
      repoQuery('coollabsio/coolify'),
      { file: 'ghsa/repo-coolify-1.json', headers: { link: `<${page2}>; rel="next"` } },
    ],
    [page2, { file: 'ghsa/repo-coolify-2.json' }],
    [repoQuery('traefik/traefik'), { file: 'ghsa/repo-traefik.json' }],
    [repoQuery('moby/moby'), { file: 'ghsa/repo-moby.json' }],
    [repoQuery('redis/redis'), { file: 'ghsa/repo-redis.json' }],
    ...globalQueries.map((q): [string, Route] => [
      q.url,
      q.url.includes('github.com%2Ftraefik%2Ftraefik%2Fv3')
        ? { file: 'ghsa/global-traefik-v3.json' }
        : { body: '[]' },
    ]),
    [
      'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/59xxx/CVE-2026-59734.json',
      { file: 'cve/CVE-2026-59734.json' },
    ],
    ['https://endoflife.date/api/v1/products/postgresql', { file: 'endoflife/postgresql.json' }],
    [KEV_URLS[0], { file: 'kev/known_exploited_vulnerabilities.json' }],
    [
      `${EPSS_API}?cve=CVE-2025-49844,CVE-2025-59157,CVE-2026-115538,CVE-2026-120153,CVE-2026-120154,CVE-2026-25243,CVE-2026-34158,CVE-2026-34592,CVE-2026-34597,CVE-2026-59734,CVE-2026-88010&limit=100`,
      { file: 'epss/feed-cves.json' },
    ],
  ]);
}

interface Seen {
  url: string;
  headers: Record<string, string>;
}

function fakeFetch(table: Map<string, Route>, seen: Seen[]): FetchLike {
  return (url, init) => {
    seen.push({ url, headers: init?.headers ?? {} });
    const route = table.get(url);
    if (route === undefined) return Promise.resolve(new Response('not found', { status: 404 }));
    const body =
      route.body ?? (route.file === undefined ? '' : readFileSync(join(fixtures, route.file)));
    return Promise.resolve(
      new Response(body, {
        status: route.status ?? 200,
        headers: { 'x-ratelimit-remaining': '4999', ...route.headers },
      }),
    );
  };
}

let scratch: string | undefined;
afterEach(() => {
  if (scratch !== undefined) rmSync(scratch, { recursive: true, force: true });
  scratch = undefined;
});

function setup() {
  scratch = mkdtempSync(join(tmpdir(), 'advisorydeck-ingest-'));
  const cacheDir = join(scratch, 'cache');
  cpSync(
    join(fixtures, 'cvelist/2026-11-14_all_CVEs_at_midnight.zip.zip'),
    join(cacheDir, '2026-11-14_all_CVEs_at_midnight.zip.zip'),
  );
  return { dataDir: join(scratch, 'data'), cacheDir };
}

function options(
  dirs: { dataDir: string; cacheDir: string },
  seen: Seen[],
  extra: Partial<RunOptions> = {},
  table = routes(),
  token?: string,
): RunOptions {
  return {
    http: new Http({
      fetch: fakeFetch(table, seen),
      githubToken: token,
      sleep: () => Promise.resolve(),
    }),
    dataDir: dirs.dataDir,
    cacheDir: dirs.cacheDir,
    now: new Date('2026-11-16T00:00:00Z'),
    ...extra,
  };
}

function snapshot(dir: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const name of readdirSync(dir, { recursive: true, encoding: 'utf8' }).sort()) {
    const path = join(dir, name);
    try {
      out.set(relative(dir, path), readFileSync(path, 'utf8'));
    } catch {
      // directory
    }
  }
  return out;
}

// eslint-disable-next-line @typescript-eslint/no-unnecessary-type-parameters -- typed fixture reader
function readJson<T>(path: string): T {
  return JSON.parse(readFileSync(path, 'utf8')) as T;
}

async function firstRun(dirs: { dataDir: string; cacheDir: string }, seen: Seen[] = []) {
  return runIngest(
    options(dirs, seen, {
      backfill: true,
      baselineFile: join(dirs.cacheDir, '2026-11-14_all_CVEs_at_midnight.zip.zip'),
      since: '2025-01-01',
    }),
  );
}

describe('ingest run (recorded fixtures, no network)', () => {
  it('backfills, applies deltas and writes the feed contract', async () => {
    const dirs = setup();
    const report = await firstRun(dirs);
    expect(report.errors).toEqual([]);

    const ids = readdirSync(join(dirs.dataDir, 'advisories')).sort();
    expect(ids).toEqual([
      'CVE-2025-49844.json',
      'CVE-2025-59157.json',
      'CVE-2026-115538.json',
      'CVE-2026-120153.json',
      'CVE-2026-120154.json',
      'CVE-2026-25243.json',
      'CVE-2026-34158.json',
      'CVE-2026-34592.json',
      'CVE-2026-34597.json',
      'CVE-2026-59734.json',
      'CVE-2026-88010.json',
      'GHSA-782c-3jq5-fw4j.json',
      'GHSA-p956-6gvv-mxqp.json',
      'GHSA-x5pf-cqh3-2gv8.json',
    ]);
    for (const name of ids) {
      const advisory = readJson<Advisory>(join(dirs.dataDir, 'advisories', name));
      expect(validateAgainst('advisory', advisory)).toEqual([]);
      // Every advisory was looked up in the (recorded) KEV catalog; none of these is listed.
      expect(advisory.kev).toEqual({ listed: false, added_at: null, checked: true });
    }

    // The CVE a GHSA names was fetched on its own and joined the cluster.
    const coolify = readJson<Advisory>(join(dirs.dataDir, 'advisories/CVE-2026-59734.json'));
    expect(coolify.aliases).toEqual(['GHSA-4fhp-xqqp-w7vv']);
    expect(coolify.sources.map((s) => s.type)).toEqual(['cve-cna', 'epss', 'ghsa']);
    expect(coolify.epss).toEqual({ score: 0.00811, percentile: 0.57517, date: '2026-11-15' });
    expect(coolify.affected).toEqual([
      { product: 'coolify', ranges: [{ introduced: '0', fixed: '4.0.0-beta.469' }] },
    ]);

    // Repository and global copies of one GHSA are one advisory.
    const traefik = readJson<Advisory>(join(dirs.dataDir, 'advisories/GHSA-p956-6gvv-mxqp.json'));
    expect(traefik.sources).toHaveLength(1);

    const api = join(dirs.dataDir, 'api/v1');
    const manifest = readJson<Manifest>(join(api, 'manifest.json'));
    expect(validateAgainst('manifest', manifest)).toEqual([]);
    expect(Object.keys(manifest.products)).toEqual([
      'angular',
      'apache-httpd',
      'astro',
      'authelia',
      'authentik',
      'beszel',
      'bun',
      'caddy',
      'code-server',
      'coder',
      'containerd',
      'coolify',
      'couchdb',
      'deno',
      'directus',
      'discourse',
      'django',
      'docker-engine',
      'docker-registry',
      'dokku',
      'dokploy',
      'dotnet',
      'dozzle',
      'dragonfly',
      'drupal',
      'elasticsearch',
      'envoy',
      'express',
      'fastapi',
      'fastify',
      'filebrowser',
      'flask',
      'flowise',
      'ghost',
      'gin',
      'gitea',
      'gitlab',
      'grafana',
      'haproxy',
      'harbor',
      'home-assistant',
      'hono',
      'immich',
      'jellyfin',
      'k3s',
      'keycloak',
      'kubernetes',
      'laravel',
      'logto',
      'loki',
      'mariadb',
      'mattermost',
      'memcached',
      'mongodb',
      'mysql',
      'n8n',
      'nats',
      'nestjs',
      'netdata',
      'nextcloud',
      'nextjs',
      'nginx',
      'nginx-proxy-manager',
      'nocodb',
      'nodejs',
      'nuxt',
      'open-webui',
      'openbao',
      'paperless-ngx',
      'phoenix',
      'php',
      'pocket-id',
      'podman',
      'portainer',
      'postgresql',
      'prometheus',
      'python',
      'qdrant',
      'rabbitmq',
      'react-router',
      'redis',
      'rocket-chat',
      'runc',
      'seaweedfs',
      'spring-boot',
      'spring-framework',
      'surrealdb',
      'sveltekit',
      'symfony',
      'tomcat',
      'traefik',
      'typesense',
      'uptime-kuma',
      'valkey',
      'vault',
      'vaultwarden',
      'wordpress',
      'zabbix',
      'zitadel',
    ]);
    for (const [slug, entry] of Object.entries(manifest.products)) {
      const bytes = readFileSync(join(api, 'products', `${slug}.json`));
      const feed = JSON.parse(bytes.toString('utf8')) as ProductFeed;
      expect(validateAgainst('product-feed', feed)).toEqual([]);
      expect(entry?.etag).toBe(etagOf(bytes));
      expect(entry?.advisories).toBe(feed.advisories.length);
      const dates = feed.advisories.map((a) => a.published_at);
      expect(dates).toEqual([...dates].sort().reverse());
    }
    const postgres = readJson<ProductFeed>(join(api, 'products/postgresql.json'));
    expect(postgres.product.branches[0]).toEqual({
      name: '18',
      eol: false,
      eol_date: '2030-11-14',
      latest: '18.7',
    });
    expect(postgres.advisories.map((a) => a.id)).toEqual(['CVE-2026-120154', 'CVE-2026-120153']);

    const quality = readJson<Record<string, string[]>>(join(dirs.dataDir, 'quality.json'));
    expect(Object.keys(quality)).toContain('CVE-2026-34592');

    expect(report.state.cvelist).toEqual({ day: '2026-11-15', release: 'cve_2026-11-15_0100Z' });
    expect(report.state.ghsa['repo:coollabsio/coolify']).toBe('2026-07-07T15:34:51Z');
  });

  it('is incremental and idempotent: a rerun reads only up to the cursors and changes nothing', async () => {
    const dirs = setup();
    await firstRun(dirs);
    const before = snapshot(dirs.dataDir);
    const seen: Seen[] = [];
    const report = await runIngest(options(dirs, seen, { now: new Date('2026-11-16T06:00:00Z') }));
    expect(report.errors).toEqual([]);
    expect(snapshot(dirs.dataDir)).toEqual(before);
    expect(seen.some((s) => s.url.endsWith('.zip'))).toBe(false);
    expect(
      seen.filter((s) => s.url.includes('coollabsio/coolify/security-advisories')),
    ).toHaveLength(1);
    // EPSS changes once a day: six hours later it is not asked again.
    expect(seen.some((s) => s.url.startsWith(EPSS_API))).toBe(false);
  });

  it('publishes advisories as not checked when KEV was never read, and keeps a stored catalog', async () => {
    const dirs = setup();
    const table = routes();
    for (const url of KEV_URLS) table.set(url, { status: 500, body: 'down' });
    const report = await runIngest(
      options(dirs, [], { skip: new Set(['cve', 'ghsa', 'epss']), since: '2025-01-01' }, table),
    );
    expect(report.warnings.join('\n')).toContain('kev:');
    expect(report.warnings.join('\n')).toContain('not checked');

    const dirs2 = setup();
    await firstRun(dirs2);
    const later = await runIngest(
      options(
        dirs2,
        [],
        { skip: new Set(['cve', 'ghsa']), now: new Date('2026-11-17T00:00:00Z') },
        table,
      ),
    );
    expect(later.warnings.join('\n')).toContain('kept the stored catalog');
    const advisory = readJson<Advisory>(join(dirs2.dataDir, 'advisories/CVE-2026-120154.json'));
    expect(advisory.kev.checked).toBe(true);
  });

  it('rebuilds the same outputs offline from data/sources', async () => {
    const dirs = setup();
    await firstRun(dirs);
    const before = snapshot(dirs.dataDir);
    const seen: Seen[] = [];
    await runIngest(options(dirs, seen, { offline: true }));
    expect(seen).toEqual([]);
    expect(snapshot(dirs.dataDir)).toEqual(before);
  });

  it('sends GITHUB_TOKEN to api.github.com only, and works without it', async () => {
    const dirs = setup();
    const withToken: Seen[] = [];
    await runIngest(options(dirs, withToken, { skip: new Set(['cve']) }, routes(), 'test-token'));
    for (const { url, headers } of withToken) {
      const expected = new URL(url).hostname === 'api.github.com' ? 'Bearer test-token' : undefined;
      expect(headers['Authorization']).toBe(expected);
    }
    const dirs2 = setup();
    const without: Seen[] = [];
    const report = await runIngest(options(dirs2, without, { skip: new Set(['cve']) }));
    expect(report.errors).toEqual([]);
    expect(without.every(({ headers }) => headers['Authorization'] === undefined)).toBe(true);
  });

  it('stops GHSA on a rate limit, keeps its cursors and still writes a valid feed', async () => {
    const dirs = setup();
    const table = routes();
    const reset = String(Math.floor(Date.now() / 1000) + 3600);
    table.set(repoQuery('coollabsio/coolify'), {
      status: 403,
      body: '{"message":"API rate limit exceeded"}',
      headers: { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': reset },
    });
    const report = await runIngest(options(dirs, [], { skip: new Set(['cve']) }, table));
    expect(report.errors.join('\n')).toContain('rate limit');
    expect(report.state.ghsa['repo:coollabsio/coolify']).toBeUndefined();
    const manifest = readJson<Manifest>(join(dirs.dataDir, 'api/v1/manifest.json'));
    expect(validateAgainst('manifest', manifest)).toEqual([]);
  });

  it('asks for a backfill when cvelistV5 has no cursor', async () => {
    const dirs = setup();
    const report = await runIngest(options(dirs, [], { skip: new Set(['ghsa', 'branches']) }));
    expect(report.errors.join('\n')).toContain('--backfill');
  });
});

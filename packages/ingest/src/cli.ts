import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { loadCatalog, repoRoot } from '@advisorydeck/contract';
import { ghsaQueries, planGhsaRequests } from './ghsa.ts';
import { Http } from './http.ts';
import { runIngest, sourceNames, type SourceName } from './run.ts';
import { Store } from './store.ts';

const usage = `pnpm ingest [options]

Fetches advisories for the catalog products into data/ (advisories, the v1 feed and the state).

  --backfill            rebuild the CVE records from the cvelistV5 midnight baseline (large download)
  --baseline <file>     use a baseline zip already on disk for --backfill
  --cache-dir <dir>     where downloads are kept (default .cache/ingest)
  --since <YYYY-MM-DD>  keep advisories published on or after this date (default: one year back)
  --skip <source>       skip cve, ghsa, branches, kev, epss or nvd (repeatable)
  --offline             no network: rebuild the outputs from data/sources
  --data-dir <dir>      write somewhere other than data/
  --anonymous           run without GITHUB_TOKEN even when the run needs more GitHub requests
                        than the anonymous limit allows (the GHSA sources stop at the limit)
  --help

GITHUB_TOKEN is needed for the full catalog: without it GitHub allows 60 API requests an hour,
fewer than one run of the catalog's GHSA queries can take, so ingest refuses to start unless
--anonymous is given. Any token works, no scopes needed. KEV, EPSS and NVD need no key.`;

const { values } = parseArgs({
  options: {
    backfill: { type: 'boolean', default: false },
    baseline: { type: 'string' },
    'cache-dir': { type: 'string' },
    since: { type: 'string' },
    skip: { type: 'string', multiple: true, default: [] },
    offline: { type: 'boolean', default: false },
    'data-dir': { type: 'string' },
    anonymous: { type: 'boolean', default: false },
    help: { type: 'boolean', default: false },
  },
});

if (values.help) {
  console.log(usage);
  process.exit(0);
}
if (values.since !== undefined && !/^\d{4}-\d{2}-\d{2}$/.test(values.since)) {
  console.error('--since takes a date as YYYY-MM-DD');
  process.exit(2);
}
const skip = new Set<SourceName>();
for (const name of values.skip) {
  const source = sourceNames.find((s) => s === name);
  if (source === undefined) {
    console.error(`--skip takes ${sourceNames.join(', ')}, not ${name}`);
    process.exit(2);
  }
  skip.add(source);
}

const log = (message: string) => {
  console.error(`ingest: ${message}`);
};
const http = new Http({ githubToken: process.env['GITHUB_TOKEN'], log });
if (!http.authenticated && !values.offline && !skip.has('ghsa')) {
  await checkAnonymousBudget(http);
}

const report = await runIngest({
  http,
  log,
  backfill: values.backfill,
  baselineFile: values.baseline,
  since: values.since,
  offline: values.offline,
  skip,
  ...(values['cache-dir'] === undefined ? {} : { cacheDir: values['cache-dir'] }),
  ...(values['data-dir'] === undefined ? {} : { dataDir: values['data-dir'] }),
});

for (const warning of report.warnings) log(`warning: ${warning}`);
for (const error of report.errors) log(`error: ${error}`);
const { output } = report;
log(
  `${report.advisories} advisories; ${output.advisoriesWritten} written, ${output.advisoriesRemoved} removed; products changed: ${output.productsChanged.join(', ') || 'none'}`,
);
if (http.rateRemaining !== undefined)
  log(`GitHub API requests left this hour: ${http.rateRemaining}`);
process.exit(report.errors.length > 0 ? 1 : 0);

/**
 * Without a token GitHub allows 60 REST requests an hour. Counts what this run needs (one request
 * per GHSA query, the page cap for a query without a cursor, two cvelistV5 release listings) and
 * refuses to start when that is more than the hour has left, unless --anonymous is given.
 */
async function checkAnonymousBudget(client: Http): Promise<void> {
  const root = repoRoot();
  const catalog = loadCatalog(root);
  const state = new Store(values['data-dir'] ?? join(root, 'data')).readState() ?? { ghsa: {} };
  const plan = planGhsaRequests(ghsaQueries(catalog.entries), state, false);
  const listings = skip.has('cve') ? 0 : 2;
  const needed = plan.worstCase + listings;
  let remaining = 60;
  try {
    // GET /rate_limit does not count against the limit.
    const limit = await client.json<{ resources?: { core?: { remaining?: number } } }>(
      'https://api.github.com/rate_limit',
    );
    remaining = limit?.data.resources?.core?.remaining ?? remaining;
  } catch {
    // keep the default
  }
  const detail = `this run needs up to ${needed} GitHub API requests (${plan.minimum} GHSA queries, ${plan.withoutCursor} of them reading their full history, plus ${listings} cvelistV5 listings) and ${remaining} of the anonymous 60 an hour are left`;
  if (needed <= remaining) {
    log(`no GITHUB_TOKEN: ${detail}. Set GITHUB_TOKEN for the full catalog.`);
    return;
  }
  if (values.anonymous) {
    log(
      `warning: no GITHUB_TOKEN: ${detail}. Continuing because of --anonymous: the GHSA sources stop at the limit, keep their cursors and the run exits 1.`,
    );
    return;
  }
  console.error(
    `ingest: no GITHUB_TOKEN: ${detail}.\n` +
      'Set GITHUB_TOKEN (any GitHub token, no scopes needed; in Actions github.token), or pass --anonymous to run anyway, or --skip ghsa.',
  );
  process.exit(2);
}

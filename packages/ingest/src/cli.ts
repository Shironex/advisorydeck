import { parseArgs } from 'node:util';
import { Http } from './http.ts';
import { runIngest, sourceNames, type SourceName } from './run.ts';

const usage = `pnpm ingest [options]

Fetches advisories for the catalog products into data/ (advisories, the v1 feed and the state).

  --backfill            rebuild the CVE records from the cvelistV5 midnight baseline (large download)
  --baseline <file>     use a baseline zip already on disk for --backfill
  --cache-dir <dir>     where downloads are kept (default .cache/ingest)
  --since <YYYY-MM-DD>  keep advisories published on or after this date (default: one year back)
  --skip <source>       skip cve, ghsa, branches, kev, epss or nvd (repeatable)
  --offline             no network: rebuild the outputs from data/sources
  --data-dir <dir>      write somewhere other than data/
  --help

GITHUB_TOKEN raises the GitHub API limit from 60 to 5000 requests an hour; it is optional.
KEV, EPSS and NVD need no key.`;

const { values } = parseArgs({
  options: {
    backfill: { type: 'boolean', default: false },
    baseline: { type: 'string' },
    'cache-dir': { type: 'string' },
    since: { type: 'string' },
    skip: { type: 'string', multiple: true, default: [] },
    offline: { type: 'boolean', default: false },
    'data-dir': { type: 'string' },
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
if (!http.authenticated && !values.offline)
  log('no GITHUB_TOKEN: GitHub allows 60 requests an hour');

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

/** Atom 1.0 (RFC 4287) feeds of advisories. */
import { fixesOf, type AdvisoryView } from './feed.ts';
import { escapeHtml } from './markdown.ts';
import { absoluteUrl, advisoryPath, SITE_NAME } from './site.ts';

export interface AtomOptions {
  title: string;
  /** Site path of the feed itself. */
  selfPath: string;
  /** Site path of the matching HTML page. */
  pagePath: string;
  updated: string | null;
  advisories: readonly AdvisoryView[];
}

const xml = escapeHtml;

function entry(advisory: AdvisoryView): string {
  const url = absoluteUrl(advisoryPath(advisory.id));
  const products = advisory.affected.map((a) => a.name).join(', ');
  const fixes = advisory.affected
    .map((a) => {
      const list = fixesOf(a);
      if (a.ranges.length === 0) {
        return `${a.name}: affected versions unknown, check manually`;
      }
      return `${a.name}: ${list.length > 0 ? `fixed in ${list.join(', ')}` : 'no fix listed'}`;
    })
    .join('; ');
  const severity =
    advisory.severity.score === null
      ? advisory.severity.level
      : `${advisory.severity.level} ${advisory.severity.score.toFixed(1)}`;
  const kev = advisory.kev.state === 'listed' ? ' Listed in CISA KEV (exploited in the wild).' : '';
  const text = `[${severity.toUpperCase()}] ${products}. ${fixes}.${kev}\n\n${advisory.summary}`;
  return [
    '  <entry>',
    `    <id>${xml(url)}</id>`,
    `    <title>${xml(`[${advisory.severity.level}] ${advisory.id}: ${advisory.title}`)}</title>`,
    `    <link rel="alternate" type="text/html" href="${xml(url)}"/>`,
    `    <published>${xml(advisory.publishedAt)}</published>`,
    `    <updated>${xml(advisory.modifiedAt)}</updated>`,
    ...advisory.affected.map((a) => `    <category term="${xml(a.slug)}" label="${xml(a.name)}"/>`),
    `    <summary type="text">${xml(text)}</summary>`,
    '  </entry>',
  ].join('\n');
}

export function atomFeed(options: AtomOptions): string {
  const updated =
    options.advisories.reduce<string | null>(
      (latest, a) => (latest === null || a.modifiedAt > latest ? a.modifiedAt : latest),
      null,
    ) ??
    options.updated ??
    new Date(0).toISOString();
  return [
    '<?xml version="1.0" encoding="utf-8"?>',
    '<feed xmlns="http://www.w3.org/2005/Atom">',
    `  <id>${xml(absoluteUrl(options.selfPath))}</id>`,
    `  <title>${xml(options.title)}</title>`,
    `  <subtitle>${xml(`${SITE_NAME}: security advisories for the software self-hosters run. Data from the CVE Program, GitHub Advisory Database and endoflife.date; see the data sources page.`)}</subtitle>`,
    `  <link rel="self" type="application/atom+xml" href="${xml(absoluteUrl(options.selfPath))}"/>`,
    `  <link rel="alternate" type="text/html" href="${xml(absoluteUrl(options.pagePath))}"/>`,
    `  <updated>${xml(updated)}</updated>`,
    `  <author><name>${SITE_NAME}</name></author>`,
    ...options.advisories.map(entry),
    '</feed>',
    '',
  ].join('\n');
}

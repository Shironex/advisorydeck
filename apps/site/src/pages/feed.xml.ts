import type { APIRoute } from 'astro';
import { atomFeed } from '../lib/atom.ts';
import { advisoriesOf, loadSiteData } from '../lib/feed.ts';

/** The newest advisories across every product. */
export const GET: APIRoute = () => {
  const data = loadSiteData();
  const body = atomFeed({
    title: 'Advisorydeck: all advisories',
    selfPath: 'feed.xml',
    pagePath: '',
    updated: data.generatedAt,
    advisories: advisoriesOf(data, data.advisoryOrder.slice(0, 50)),
  });
  return new Response(body, { headers: { 'Content-Type': 'application/atom+xml; charset=utf-8' } });
};

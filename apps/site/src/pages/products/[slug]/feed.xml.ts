import type { APIRoute, GetStaticPaths } from 'astro';
import { atomFeed } from '../../../lib/atom.ts';
import { advisoriesOf, loadSiteData } from '../../../lib/feed.ts';
import { productFeedPath, productPath } from '../../../lib/site.ts';

export const getStaticPaths = (() =>
  loadSiteData().products.map((p) => ({ params: { slug: p.slug } }))) satisfies GetStaticPaths;

/** Every advisory of one product, newest first. */
export const GET: APIRoute = ({ params }) => {
  const data = loadSiteData();
  const product = data.products.find((p) => p.slug === params['slug']);
  if (product === undefined) {
    return new Response('not found', { status: 404 });
  }
  const body = atomFeed({
    title: `Advisorydeck: ${product.name} advisories`,
    selfPath: productFeedPath(product.slug),
    pagePath: productPath(product.slug),
    updated: product.generatedAt,
    advisories: advisoriesOf(data, product.advisoryIds),
  });
  return new Response(body, { headers: { 'Content-Type': 'application/atom+xml; charset=utf-8' } });
};

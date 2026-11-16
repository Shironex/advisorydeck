import type { APIRoute } from 'astro';
import { CATEGORY_LABELS, loadSiteData } from '../lib/feed.ts';
import { advisoryPath, href, productPath } from '../lib/site.ts';

/** The search index the top bar loads on first use: products, then advisories newest first. */
export const GET: APIRoute = () => {
  const data = loadSiteData();
  const entries = [
    ...data.products.map((p) => ({
      t: p.name,
      d: `${CATEGORY_LABELS[p.category].name}, ${p.advisoryIds.length} advisories`,
      p: '',
      u: href(productPath(p.slug)),
    })),
    ...data.advisoryOrder.flatMap((id) => {
      const a = data.advisories.get(id);
      if (a === undefined) return [];
      return [
        {
          t: [a.id, ...a.aliases].join(' '),
          d: a.title,
          p: a.affected.map((x) => x.name).join(', '),
          u: href(advisoryPath(a.id)),
        },
      ];
    }),
  ];
  return new Response(JSON.stringify(entries), {
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
  });
};

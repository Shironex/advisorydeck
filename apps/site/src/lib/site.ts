/** Site-wide constants and URL helpers. */

export const REPO_URL = 'https://github.com/Shironex/advisorydeck';
export const SITE_NAME = 'Advisorydeck';

/** Joins a site path onto the configured base (for example /advisorydeck). */
export function href(path: string): string {
  const base = import.meta.env.BASE_URL.replace(/\/+$/, '');
  const clean = path.replace(/^\/+/, '');
  return `${base}/${clean}`;
}

/** Absolute URL of a site path, for Atom feeds and the generator's feed URL. */
export function absoluteUrl(path: string): string {
  return new URL(href(path), import.meta.env.SITE).toString();
}

/** The feed base URL the image polls: this site's api/v1/. */
export function feedBaseUrl(): string {
  return absoluteUrl('api/v1/');
}

export const advisoryPath = (id: string): string => `advisories/${id}/`;
export const productPath = (slug: string): string => `products/${slug}/`;
export const productFeedPath = (slug: string): string => `products/${slug}/feed.xml`;
export const categoryPath = (category: string): string => `categories/${category}/`;

/** The GitHub issue form for a wrong note, prefilled with the advisory id. */
export function wrongNoteUrl(advisoryId: string): string {
  const params = new URLSearchParams({
    template: 'wrong-note.yml',
    title: `wrong note: ${advisoryId}`,
    advisory: advisoryId,
  });
  return `${REPO_URL}/issues/new?${params.toString()}`;
}

/** The GitHub issue form to propose or request a note. */
export function requestNoteUrl(advisoryId: string, products: readonly string[]): string {
  const params = new URLSearchParams({
    template: 'curated-note.yml',
    title: `note: ${advisoryId} ${products.join(' ')}`,
    advisory: advisoryId,
    products: products.join(', '),
  });
  return `${REPO_URL}/issues/new?${params.toString()}`;
}

/** The generator with one product picked (the URL fragment never reaches a server). */
export const generatorPath = (slug: string, version = '', floating = false): string =>
  `generator/#p=${slug}~${floating ? 'f' : 'e'}~${encodeURIComponent(version)}`;

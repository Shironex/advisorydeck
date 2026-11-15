import { loadCatalog, type CatalogEntry } from '@advisorydeck/contract';
import { describe, expect, it } from 'vitest';
import { buildSourceIndex } from '../src/index.ts';

const catalog = loadCatalog();

describe('source index', () => {
  it('maps every upstream identifier in the catalog to exactly one product', () => {
    expect(catalog.issues).toEqual([]);
    const { index, issues } = buildSourceIndex(catalog.entries);
    expect(issues).toEqual([]);
    expect(index.ghsaRepos.get('traefik/traefik')).toBe('traefik');
    expect(index.ghsaRepos.get('coollabsio/coolify')).toBe('coolify');
    expect(index.ghsaPackages.get('go:github.com/moby/moby/v2')).toBe('docker-engine');
    expect(index.cna.get('PostgreSQL')).toEqual([{ slug: 'postgresql', products: ['PostgreSQL'] }]);
    expect(index.cna.get('GitHub_M')).toEqual([
      { slug: 'redis', products: ['redis'], vendor: 'redis' },
    ]);
  });

  it('reports two products claiming the same repository', () => {
    const traefik = catalog.entries.find((entry) => entry.product.slug === 'traefik');
    if (traefik === undefined) throw new Error('traefik missing');
    const copy: CatalogEntry = {
      file: 'catalog/proxies/other.yml',
      product: { ...traefik.product, slug: 'other' },
    };
    const { issues } = buildSourceIndex([traefik, copy]);
    expect(issues.map((issue) => issue.message)).toContain(
      'traefik/traefik is already claimed by traefik',
    );
  });
});

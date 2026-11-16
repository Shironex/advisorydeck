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
    expect(index.ghsaRepos.get('moby/moby')).toBe('docker-engine');
    expect(index.ghsaPackages.get('go:github.com/traefik/traefik/v3')).toBe('traefik');
    expect(index.cna.get('PostgreSQL')).toEqual([{ slug: 'postgresql', products: ['PostgreSQL'] }]);
    const github = index.cna.get('GitHub_M') ?? [];
    expect(github).toContainEqual({ slug: 'redis', products: ['redis'], vendor: 'redis' });
    expect(github).toContainEqual({ slug: 'caddy', products: ['caddy'], vendor: 'caddyserver' });
    // GitHub files for many vendors: every GitHub_M source names its vendor.
    expect(github.every((claim) => claim.vendor !== undefined)).toBe(true);
    expect(index.ghsaPackages.get('go:code.gitea.io/gitea')).toBe('gitea');
    expect(index.ghsaRepos.has('go-gitea/gitea')).toBe(false);
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

  it('takes every product of a vendor only with a vendor named', () => {
    const base = catalog.entries[0]?.product;
    if (base === undefined) throw new Error('empty catalog');
    const go = (vendor?: string): CatalogEntry => ({
      file: 'catalog/runtimes/go.yml',
      product: {
        ...base,
        slug: 'go',
        sources: [
          {
            type: 'cve-cna',
            assigner: 'Go',
            products: ['*'],
            ...(vendor === undefined ? {} : { vendor }),
          },
        ],
      },
    });
    expect(buildSourceIndex([go('Go standard library')]).issues).toEqual([]);
    expect(buildSourceIndex([go()]).issues.map((i) => i.message)).toEqual([
      'Go products ["*"] needs a vendor, or it takes the whole assigner',
    ]);
    const other: CatalogEntry = {
      file: 'catalog/runtimes/net.yml',
      product: {
        ...base,
        slug: 'net',
        sources: [
          {
            type: 'cve-cna',
            assigner: 'Go',
            vendor: 'Go standard library',
            products: ['net/http'],
          },
        ],
      },
    };
    expect(
      buildSourceIndex([go('Go standard library'), other]).issues.map((i) => i.message),
    ).toEqual(['Go products overlap with go']);
  });
});

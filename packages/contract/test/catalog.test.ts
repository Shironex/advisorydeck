import { describe, expect, it } from 'vitest';
import { loadCatalog, versionFromTag } from '../src/index.ts';

const catalog = loadCatalog();
const bySlug = new Map(catalog.entries.map((entry) => [entry.product.slug, entry.product]));

function tagPattern(slug: string): string {
  const pattern = bySlug.get(slug)?.images[0]?.tag_pattern;
  if (pattern === undefined) throw new Error(`${slug} has no image`);
  return pattern;
}

describe('catalog', () => {
  it('loads every entry without problems', () => {
    expect(catalog.issues).toEqual([]);
    expect([...bySlug.keys()].sort()).toEqual([
      'coolify',
      'docker-engine',
      'postgresql',
      'redis',
      'traefik',
    ]);
  });

  it('gives every product at least one machine-readable source', () => {
    for (const product of bySlug.values()) {
      const machine = product.sources.filter((source) => source.type !== 'vendor-page');
      expect(machine.length, product.slug).toBeGreaterThan(0);
    }
  });

  // Tags below were read from the registries on 2026-11-16.
  it.each([
    ['postgresql', '17', '17'],
    ['postgresql', '17.12-alpine3.24', '17.12'],
    ['postgresql', '16-trixie', '16'],
    ['postgresql', 'alpine', undefined],
    ['traefik', 'v3.7.19', '3.7.19'],
    ['traefik', '3.7', '3.7'],
    ['traefik', 'v3.8.0-rc.3-nanoserver-ltsc2025', '3.8.0-rc.3'],
    ['traefik', 'mimolette-nanoserver-ltsc2025', undefined],
    ['redis', '8.8.4-alpine', '8.8.4'],
    ['redis', '8.12-rc3-trixie', '8.12-rc3'],
    ['redis', '7.4', '7.4'],
    ['coolify', '4.0.0-beta.451', '4.0.0-beta.451'],
    ['coolify', 'latest', undefined],
    ['coolify', 'fix-webhook-migration-conflict-amd64', undefined],
    ['docker-engine', '29.9.3-dind', '29.9.3'],
    ['docker-engine', '29.10.0-rc.2-dind-rootless', '29.10.0-rc.2'],
    ['docker-engine', '29-cli', '29'],
    ['docker-engine', 'dind', undefined],
  ] as const)('reads %s tag %s as %s', (slug, tag, version) => {
    expect(versionFromTag(tagPattern(slug), tag)).toBe(version);
  });
});

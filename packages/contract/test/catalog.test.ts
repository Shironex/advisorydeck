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
      'apache-httpd',
      'authelia',
      'caddy',
      'containerd',
      'coolify',
      'docker-engine',
      'dokploy',
      'elasticsearch',
      'ghost',
      'gitea',
      'gitlab',
      'grafana',
      'haproxy',
      'immich',
      'jellyfin',
      'mongodb',
      'open-webui',
      'postgresql',
      'prometheus',
      'rabbitmq',
      'redis',
      'traefik',
      'uptime-kuma',
      'vaultwarden',
      'zitadel',
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
    ['mongodb', '8.0.38-noble', '8.0.38'],
    ['mongodb', '9.0.8-resolute', '9.0.8'],
    ['mongodb', '7-jammy', '7'],
    ['mongodb', 'noble', undefined],
    ['rabbitmq', '4.4.0-management-alpine', '4.4.0'],
    ['rabbitmq', '4.3', '4.3'],
    ['rabbitmq', 'management', undefined],
    ['elasticsearch', '9.5.5', '9.5.5'],
    ['caddy', '2.11.9-alpine', '2.11.9'],
    ['caddy', '2.11.9-builder-alpine', undefined],
    ['apache-httpd', '2.4.71-alpine3.24', '2.4.71'],
    ['apache-httpd', '2.4', '2.4'],
    ['haproxy', '3.4.2-alpine', '3.4.2'],
    ['haproxy', '3.5-dev12-alpine', undefined],
    ['haproxy', 'lts', undefined],
    ['dokploy', 'v0.31.2', '0.31.2'],
    ['dokploy', 'canary', undefined],
    ['gitea', '28.4.0-rootless', '28.4.0'],
    ['gitea', '1.27.0-rc0', '1.27.0-rc0'],
    ['gitea', '28-nightly', undefined],
    ['gitlab', '19.4.7-ce.0', '19.4.7'],
    ['gitlab', 'latest', undefined],
    ['grafana', '13.3.1-ubuntu', '13.3.1'],
    ['grafana', '12.4.3-security-02-ubuntu', '12.4.3'],
    ['grafana', 'main', undefined],
    ['prometheus', 'v3.16.0-rc.4-distroless', '3.16.0-rc.4'],
    ['prometheus', 'v3.15.1', '3.15.1'],
    ['uptime-kuma', '2.5.11-slim-rootless', '2.5.11'],
    ['uptime-kuma', '1.23.17-debian', '1.23.17'],
    ['uptime-kuma', 'nightly', undefined],
    ['vaultwarden', '1.37.5-alpine', '1.37.5'],
    ['vaultwarden', 'testing', undefined],
    ['zitadel', 'v2.22.0-rc.1-amd64', '2.22.0-rc.1'],
    ['zitadel', '02b4b1a60-arm64', undefined],
    ['authelia', '4.39.28', '4.39.28'],
    ['authelia', 'master', undefined],
    ['immich', 'v3.4.0', '3.4.0'],
    ['immich', 'commit-0123abcd', undefined],
    ['jellyfin', '10.11.11.20260606-153911', '10.11.11'],
    ['jellyfin', '12.4.20261026-211555', '12.4'],
    ['jellyfin', '12.4', '12.4'],
    ['jellyfin', '10.11.11-arm64.20260606-153911', undefined],
    ['jellyfin', '2026110913', undefined],
    ['ghost', '6.77.0-alpine3.23', '6.77.0'],
    ['ghost', '6-alpine', '6'],
    ['ghost', '6.77.0-next-alpine3.23', undefined],
    ['open-webui', 'v0.12.2-cuda', '0.12.2'],
    ['open-webui', 'git-0123abc-cuda', undefined],
  ] as const)('reads %s tag %s as %s', (slug, tag, version) => {
    expect(versionFromTag(tagPattern(slug), tag)).toBe(version);
  });
});

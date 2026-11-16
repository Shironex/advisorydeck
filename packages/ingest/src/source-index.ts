import type { CatalogEntry, Issue } from '@advisorydeck/contract';

/** A cvelistV5 rule: records from this assigner whose affected product (and vendor) match belong to slug. */
export interface CnaRule {
  slug: string;
  products: string[];
  vendor?: string;
}

/**
 * Lookup tables from upstream identifiers to catalog slugs. Ingest builds this once from the
 * catalog and uses it to decide which product an upstream record belongs to.
 */
export interface SourceIndex {
  /** cveMetadata.assignerShortName to rules. */
  cna: Map<string, CnaRule[]>;
  /** owner/name of a GitHub repository with security advisories, to slug. */
  ghsaRepos: Map<string, string>;
  /** owner/name to the package names (lowercase, trimmed) whose entries count, when the source names them. */
  ghsaRepoPackages: Map<string, Set<string>>;
  /** GHSA ecosystem:package to slug. */
  ghsaPackages: Map<string, string>;
  /** OSV ecosystem:package to slug. */
  osvPackages: Map<string, string>;
  /** Vendor RSS or Atom feeds and pages, for cross-checks and note triggers. */
  vendorUrls: { slug: string; url: string; kind: 'feed' | 'page' }[];
}

function claim(map: Map<string, string>, key: string, slug: string, file: string, issues: Issue[]) {
  const owner = map.get(key);
  if (owner !== undefined && owner !== slug) {
    issues.push({ file, message: `${key} is already claimed by ${owner}` });
    return;
  }
  map.set(key, slug);
}

/** Builds the source index; two products claiming the same upstream identifier is a catalog error. */
export function buildSourceIndex(entries: readonly CatalogEntry[]): {
  index: SourceIndex;
  issues: Issue[];
} {
  const index: SourceIndex = {
    cna: new Map(),
    ghsaRepos: new Map(),
    ghsaRepoPackages: new Map(),
    ghsaPackages: new Map(),
    osvPackages: new Map(),
    vendorUrls: [],
  };
  const issues: Issue[] = [];

  for (const { file, product } of entries) {
    const slug = product.slug;
    for (const source of product.sources) {
      switch (source.type) {
        case 'cve-cna': {
          const rules = index.cna.get(source.assigner) ?? [];
          const clash = rules.find(
            (rule) =>
              rule.vendor === source.vendor &&
              rule.products.some((p) => source.products.includes(p)),
          );
          if (clash !== undefined) {
            issues.push({
              file,
              message: `${source.assigner} products overlap with ${clash.slug}`,
            });
          }
          rules.push({
            slug,
            products: source.products,
            ...(source.vendor === undefined ? {} : { vendor: source.vendor }),
          });
          index.cna.set(source.assigner, rules);
          break;
        }
        case 'ghsa-repo':
          claim(index.ghsaRepos, source.repo, slug, file, issues);
          if (source.packages !== undefined) {
            index.ghsaRepoPackages.set(
              source.repo,
              new Set(source.packages.map((name) => name.trim().toLowerCase())),
            );
          }
          break;
        case 'ghsa-package':
          claim(index.ghsaPackages, `${source.ecosystem}:${source.package}`, slug, file, issues);
          break;
        case 'osv':
          claim(index.osvPackages, `${source.ecosystem}:${source.package}`, slug, file, issues);
          break;
        case 'vendor-feed':
          index.vendorUrls.push({ slug, url: source.url, kind: 'feed' });
          break;
        case 'vendor-page':
          index.vendorUrls.push({ slug, url: source.url, kind: 'page' });
          break;
      }
    }
  }
  return { index, issues };
}

/**
 * How advisories are grouped for reading: by day on the feed, by fixing release on a product
 * page. Several advisories of one product published together and sharing a fix collapse into a
 * release bundle, so one vendor release that fixes dozens of CVEs reads as one block. Display
 * only: the feed and the image are unaffected.
 */
import { SEVERITY_ORDER, type AdvisoryView, type ProductView, type SeverityLevel } from './feed.ts';
import {
  check,
  compareVersions,
  inBranch,
  isBranch,
  tryParse,
  type MatchAdvisory,
  type Scheme,
} from './match.ts';

/** What a row says about the fix, rendered as lead text followed by versions in code. */
export interface FixText {
  tone: 'fixed' | 'none' | 'unknown';
  lead: string;
  versions: string[];
  /** For unknown ranges: where to check (the vendor advisory, else the advisory page). */
  href?: string;
}

export interface RowView {
  advisory: AdvisoryView;
  /** Shown on standalone feed rows; null inside a bundle or on a product page. */
  productName: string | null;
  fix: FixText;
  /** Branches of the product this advisory affects (product page branch filter). */
  branches: string[];
}

export interface BundleView {
  key: string;
  slug: string;
  productName: string;
  day: string;
  /** The fixes the release ships: the header line. */
  fixes: string[];
  /** Highest severity first, then highest score. */
  rows: RowView[];
  counts: Record<SeverityLevel, number>;
}

export type DayItem = { kind: 'row'; row: RowView } | { kind: 'bundle'; bundle: BundleView };

export interface DayGroup {
  day: string;
  count: number;
  items: DayItem[];
}

const rank = (level: SeverityLevel): number => SEVERITY_ORDER.indexOf(level);

export function bySeverity(a: AdvisoryView, b: AdvisoryView): number {
  return (
    rank(a.severity.level) - rank(b.severity.level) ||
    (b.severity.score ?? -1) - (a.severity.score ?? -1) ||
    a.id.localeCompare(b.id)
  );
}

export function emptyCounts(): Record<SeverityLevel, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
}

function schemeOf(product: ProductView | undefined): Scheme {
  return product?.versionScheme ?? 'semver';
}

function isPrerelease(scheme: Scheme, version: string): boolean {
  const v = tryParse(scheme, version);
  return v !== null && v.pre !== null;
}

/**
 * Fix versions of one product as the feed rows show them. A fix that only exists as a
 * prerelease is left to the advisory page when a stable fix is also listed; when every fix is a
 * prerelease (Coolify 4 betas) they are the fixes.
 */
export function rowFixes(advisory: AdvisoryView, slug: string, scheme: Scheme): string[] {
  const fixes = advisory.affected
    .filter((a) => a.slug === slug)
    .flatMap((a) => a.ranges.flatMap((r) => (r.fixed === null ? [] : [r.fixed])));
  const unique = [...new Set(fixes)];
  const stable = unique.filter((f) => !isPrerelease(scheme, f));
  return stable.length > 0 ? stable : unique;
}

function hasUnknownRanges(advisory: AdvisoryView, slug: string): boolean {
  return advisory.affected.some((a) => a.slug === slug && a.ranges.length === 0);
}

function vendorUrl(advisory: AdvisoryView): string | undefined {
  return advisory.references.find((r) => r.type === 'advisory')?.url;
}

/** The release branch a version belongs to, for "Branch 18 only". */
export function branchOf(product: ProductView | undefined, version: string): string {
  const scheme = schemeOf(product);
  const v = tryParse(scheme, version);
  if (v !== null && product !== undefined) {
    for (const branch of product.branches) {
      const b = tryParse(scheme, branch.name);
      if (b !== null && isBranch(b) && inBranch(v, b)) {
        return branch.name;
      }
    }
  }
  // No branch data: semver major.minor, pg major.
  const parts = version.replace(/^v/, '').split(/[.-]/);
  return scheme === 'pg' ? (parts[0] ?? version) : parts.slice(0, 2).join('.');
}

/** Orders fix versions newest branch first. */
export function sortVersions(scheme: Scheme, versions: readonly string[]): string[] {
  return [...versions].sort((a, b) => {
    const va = tryParse(scheme, a);
    const vb = tryParse(scheme, b);
    if (va === null || vb === null) return a.localeCompare(b);
    return compareVersions(vb, va);
  });
}

function sameSet(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((x) => b.includes(x));
}

/** A standalone row: "Fixed in 29.9.3", "No fix listed yet" or "Versions unknown". */
function standaloneFix(advisory: AdvisoryView, slug: string, scheme: Scheme): FixText {
  const fixes = rowFixes(advisory, slug, scheme);
  if (fixes.length > 0) {
    return { tone: 'fixed', lead: 'Fixed in', versions: sortVersions(scheme, fixes) };
  }
  if (hasUnknownRanges(advisory, slug)) {
    const url = vendorUrl(advisory);
    return {
      tone: 'unknown',
      lead: 'Versions unknown, check vendor',
      versions: [],
      ...(url === undefined ? {} : { href: url }),
    };
  }
  return { tone: 'none', lead: 'No fix listed yet', versions: [] };
}

/** A row inside a bundle says only what differs from the bundle header. */
function bundleRowFix(
  advisory: AdvisoryView,
  product: ProductView | undefined,
  header: readonly string[],
  siblingsAddFixes: boolean,
): FixText {
  const scheme = schemeOf(product);
  const slug = product?.slug ?? advisory.affected[0]?.slug ?? '';
  const fixes = rowFixes(advisory, slug, scheme);
  if (fixes.length === 0) {
    return standaloneFix(advisory, slug, scheme);
  }
  const extra = fixes.filter((f) => !header.includes(f));
  const missing = header.filter((f) => !fixes.includes(f));
  if (missing.length === 0 && extra.length > 0) {
    return { tone: 'fixed', lead: 'Also', versions: sortVersions(scheme, extra) };
  }
  if (sameSet(fixes, header)) {
    if (header.length > 1) {
      return { tone: 'fixed', lead: `All ${header.length} branches`, versions: [] };
    }
    const only = header[0] ?? '';
    return siblingsAddFixes
      ? { tone: 'fixed', lead: `Branch ${branchOf(product, only)} only`, versions: [] }
      : { tone: 'fixed', lead: 'Fixed in', versions: [only] };
  }
  if (extra.length === 0) {
    const branches = sortVersions(scheme, fixes).map((f) => branchOf(product, f));
    return {
      tone: 'fixed',
      lead: `${branches.length === 1 ? 'Branch' : 'Branches'} ${branches.join(', ')} only`,
      versions: [],
    };
  }
  return { tone: 'fixed', lead: 'Fixed in', versions: sortVersions(scheme, fixes) };
}

/** Fixes listed by more than half of the advisories: what the release ships. */
function headerFixes(advisories: readonly AdvisoryView[], slug: string, scheme: Scheme): string[] {
  const seen = new Map<string, number>();
  for (const advisory of advisories) {
    for (const fix of rowFixes(advisory, slug, scheme)) {
      seen.set(fix, (seen.get(fix) ?? 0) + 1);
    }
  }
  const shared = [...seen].filter(([, n]) => n * 2 > advisories.length).map(([f]) => f);
  return sortVersions(scheme, shared);
}

/** The advisory in the matcher's shape. */
export function matchAdvisory(advisory: AdvisoryView): MatchAdvisory {
  return {
    id: advisory.id,
    affected: advisory.affected.map((a) => ({
      product: a.slug,
      ranges: a.ranges.map((r) => ({
        introduced: r.introduced,
        fixed: r.fixed,
        last_affected: r.lastAffected,
      })),
    })),
  };
}

/** Branches of the product this advisory affects (the matcher's answer for each branch). */
export function affectedBranches(advisory: AdvisoryView, product: ProductView): string[] {
  const shape = matchAdvisory(advisory);
  return product.branches
    .filter((b) => check(product.versionScheme, b.name, product.slug, shape).outcome === 'affected')
    .map((b) => b.name);
}

function makeBundle(
  key: string,
  day: string,
  product: ProductView | undefined,
  slug: string,
  name: string,
  advisories: readonly AdvisoryView[],
): BundleView {
  const scheme = schemeOf(product);
  const fixes = headerFixes(advisories, slug, scheme);
  const sorted = [...advisories].sort(bySeverity);
  const siblingsAddFixes = sorted.some((a) =>
    rowFixes(a, slug, scheme).some((f) => !fixes.includes(f)),
  );
  const counts = emptyCounts();
  for (const advisory of sorted) {
    counts[advisory.severity.level] += 1;
  }
  return {
    key,
    slug,
    productName: name,
    day,
    fixes,
    counts,
    rows: sorted.map((advisory) => ({
      advisory,
      productName: null,
      fix:
        fixes.length > 0
          ? bundleRowFix(advisory, product, fixes, siblingsAddFixes)
          : standaloneFix(advisory, slug, scheme),
      branches: product === undefined ? [] : affectedBranches(advisory, product),
    })),
  };
}

/**
 * The feed: advisories by publication day, newest first. Inside a day, two or more advisories
 * of one product that share a fix become a bundle; the rest stay rows.
 */
export function groupFeed(
  advisories: readonly AdvisoryView[],
  products: readonly ProductView[],
): DayGroup[] {
  const bySlug = new Map(products.map((p) => [p.slug, p]));
  const days: { day: string; list: AdvisoryView[] }[] = [];
  for (const advisory of advisories) {
    const day = advisory.publishedAt.slice(0, 10);
    const last = days.at(-1);
    if (last?.day === day) {
      last.list.push(advisory);
    } else {
      days.push({ day, list: [advisory] });
    }
  }
  return days.map(({ day, list }) => {
    const items: DayItem[] = [];
    const groups = new Map<string, AdvisoryView[]>();
    for (const advisory of list) {
      const slug = advisory.affected[0]?.slug ?? 'unknown';
      groups.set(slug, [...(groups.get(slug) ?? []), advisory]);
    }
    for (const [slug, group] of groups) {
      const product = bySlug.get(slug);
      const scheme = schemeOf(product);
      const name = product?.name ?? group[0]?.affected[0]?.name ?? slug;
      if (group.length >= 2 && headerFixes(group, slug, scheme).length > 0) {
        items.push({
          kind: 'bundle',
          bundle: makeBundle(`${day}-${slug}`, day, product, slug, name, group),
        });
        continue;
      }
      for (const advisory of group) {
        items.push({
          kind: 'row',
          row: {
            advisory,
            productName: name,
            fix: standaloneFix(advisory, slug, scheme),
            branches: product === undefined ? [] : affectedBranches(advisory, product),
          },
        });
      }
    }
    return { day, count: list.length, items };
  });
}

/** A product page: its advisories grouped by the day the fixing release was published. */
export function groupReleases(
  product: ProductView,
  advisories: readonly AdvisoryView[],
): BundleView[] {
  const days = new Map<string, AdvisoryView[]>();
  for (const advisory of advisories) {
    const day = advisory.publishedAt.slice(0, 10);
    days.set(day, [...(days.get(day) ?? []), advisory]);
  }
  return [...days].map(([day, list]) =>
    makeBundle(`rel-${day}`, day, product, product.slug, product.name, list),
  );
}

/** Advisories of the product with no known affected versions. */
export function unknownRangeAdvisories(advisories: readonly AdvisoryView[]): AdvisoryView[] {
  return advisories.filter((a) => a.affected.some((x) => x.ranges.length === 0));
}

/** A standalone row for an advisory, as the feed shows it (used by notices). */
export function standaloneRow(advisory: AdvisoryView, products: readonly ProductView[]): RowView {
  const slug = advisory.affected[0]?.slug ?? '';
  const product = products.find((p) => p.slug === slug);
  return {
    advisory,
    productName: product?.name ?? advisory.affected[0]?.name ?? slug,
    fix: standaloneFix(advisory, slug, schemeOf(product)),
    branches: [],
  };
}

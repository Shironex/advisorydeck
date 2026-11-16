/**
 * The product page version check: one installed branch or version against every advisory of
 * the product, with the matcher's rules, and the release to move to. Pure, so it runs in the
 * browser against the product JSON and in the tests against the committed feed.
 */
import {
  check,
  compareVersions,
  inBranch,
  isBranch,
  parseVersion,
  tryParse,
  type MatchAdvisory,
  type Scheme,
  type Version,
} from './match.ts';

export type Level = 'critical' | 'high' | 'medium' | 'low' | 'unknown';

export interface CheckFeed {
  product: {
    slug: string;
    name: string;
    version_scheme: Scheme;
    branches: { name: string; eol: boolean; eol_date: string | null; latest: string | null }[];
  };
  advisories: (MatchAdvisory & { severity: { level: string } })[];
}

export interface BranchInfo {
  name: string;
  eol: boolean;
  eolDate: string | null;
  latest: string | null;
}

/** What to do about the affected advisories. */
export type Advice =
  /** The latest release of the branch fixes every one. */
  | { kind: 'latest'; version: string; branch: BranchInfo }
  /** The latest release of the branch still leaves some affected or unknown. */
  | { kind: 'latest-partial'; version: string; branch: BranchInfo; left: number }
  /** No branch data: the highest listed fix, and how many it leaves. */
  | { kind: 'upgrade'; version: string; left: number }
  /** No advisory names a fix. */
  | { kind: 'none' };

export type Verdict =
  | { kind: 'invalid'; input: string }
  | {
      kind: 'affected';
      input: string;
      isBranch: boolean;
      affected: string[];
      counts: Record<Level, number>;
      unknown: string[];
      branch: BranchInfo | null;
      advice: Advice;
    }
  | { kind: 'clear'; input: string; isBranch: boolean; total: number }
  | { kind: 'unknown'; input: string; isBranch: boolean; unknown: string[]; total: number };

const LEVELS: readonly Level[] = ['critical', 'high', 'medium', 'low', 'unknown'];

function levelOf(value: string): Level {
  return (LEVELS as readonly string[]).includes(value) ? (value as Level) : 'unknown';
}

/** The branch of the product the installed value belongs to (17.10 and 17 both give 17). */
function branchFor(feed: CheckFeed, v: Version): BranchInfo | null {
  const scheme = feed.product.version_scheme;
  for (const branch of feed.product.branches) {
    const b = tryParse(scheme, branch.name);
    if (b === null || !isBranch(b)) continue;
    const same = isBranch(v) && compareVersions(v, b) === 0 && v.depth === b.depth;
    // A release, or a deeper floating tag (node 22.23 inside the endoflife.date branch 22).
    const inside = (!isBranch(v) || v.depth > b.depth) && inBranch(v, b);
    if (same || inside) {
      return {
        name: branch.name,
        eol: branch.eol,
        eolDate: branch.eol_date,
        latest: branch.latest,
      };
    }
  }
  return null;
}

export function checkInstalled(feed: CheckFeed, raw: string): Verdict {
  const input = raw.trim();
  const scheme = feed.product.version_scheme;
  const slug = feed.product.slug;
  let v: Version;
  try {
    v = parseVersion(scheme, input);
  } catch {
    return { kind: 'invalid', input };
  }
  const affected: CheckFeed['advisories'] = [];
  const fixes: string[] = [];
  const unknown: string[] = [];
  for (const advisory of feed.advisories) {
    const result = check(scheme, input, slug, advisory);
    if (result.outcome === 'affected') {
      affected.push(advisory);
      if (result.fixedIn !== '') fixes.push(result.fixedIn);
    } else if (result.outcome === 'unknown') {
      unknown.push(advisory.id);
    }
  }
  const total = feed.advisories.length;
  if (affected.length === 0) {
    return unknown.length === 0
      ? { kind: 'clear', input, isBranch: isBranch(v), total }
      : { kind: 'unknown', input, isBranch: isBranch(v), unknown, total };
  }
  const counts: Record<Level, number> = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  for (const advisory of affected) counts[levelOf(advisory.severity.level)] += 1;
  const branch = branchFor(feed, v);
  const leftAt = (version: string): number =>
    affected.filter((a) => check(scheme, version, slug, a).outcome !== 'not-affected').length;
  let advice: Advice;
  if (branch?.latest != null && tryParse(scheme, branch.latest) !== null) {
    const left = leftAt(branch.latest);
    advice =
      left === 0
        ? { kind: 'latest', version: branch.latest, branch }
        : { kind: 'latest-partial', version: branch.latest, branch, left };
  } else if (fixes.length > 0) {
    const parsed = fixes.flatMap((f) => {
      const p = tryParse(scheme, f);
      return p === null ? [] : [{ f, p }];
    });
    parsed.sort((a, b) => compareVersions(b.p, a.p));
    const highest = parsed[0]?.f ?? fixes[0] ?? '';
    advice = { kind: 'upgrade', version: highest, left: leftAt(highest) };
  } else {
    advice = { kind: 'none' };
  }
  return {
    kind: 'affected',
    input,
    isBranch: isBranch(v),
    affected: affected.map((a) => a.id),
    counts,
    unknown,
    branch,
    advice,
  };
}

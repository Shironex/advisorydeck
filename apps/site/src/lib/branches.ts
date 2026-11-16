/**
 * A per-branch summary of a product's advisories for the product page. It only reads the
 * published ranges with a plain dotted-number comparison; the matcher in the image is the
 * authority for "am I affected". Anything it cannot order (prereleases, letters) is counted as
 * "check the advisory" instead of being guessed.
 */
import type { AdvisoryView, BranchView, ProductView, RangeView } from './feed.ts';

export interface BranchRow {
  branch: BranchView;
  /** Advisories with a fix released inside this branch. */
  fixedHere: number;
  /** The highest fix inside this branch: the release that covers every listed fix. */
  highestFix: string | null;
  /** True when the branch's latest release is at or above highestFix. */
  latestCoversFixes: boolean | null;
  /** Advisories whose range runs through this branch with no fix inside it. */
  noFixHere: number;
}

function numericParts(version: string): number[] | null {
  if (!/^[0-9]+(\.[0-9]+)*$/.test(version)) {
    return null;
  }
  return version.split('.').map(Number);
}

/** Compares dotted numeric versions; null when either side is not purely numeric. */
export function compareDotted(a: string, b: string): number | null {
  const pa = numericParts(a);
  const pb = numericParts(b);
  if (pa === null || pb === null) {
    return null;
  }
  const length = Math.max(pa.length, pb.length);
  for (let i = 0; i < length; i += 1) {
    const diff = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (diff !== 0) {
      return diff < 0 ? -1 : 1;
    }
  }
  return 0;
}

export function inBranch(version: string, branch: string): boolean {
  return version === branch || version.startsWith(`${branch}.`);
}

function spansWithoutFix(range: RangeView, branch: string): boolean {
  const end = range.fixed ?? range.lastAffected;
  if (end !== null && inBranch(end, branch)) {
    return false;
  }
  const startsBefore =
    range.introduced === '0' || (compareDotted(range.introduced, branch) ?? 1) <= 0;
  if (!startsBefore && !inBranch(range.introduced, branch)) {
    return false;
  }
  if (end === null) {
    return true;
  }
  // The range ends after this branch (in a newer one) or is an open last_affected.
  return (compareDotted(end, branch) ?? -1) > 0;
}

export function branchRows(product: ProductView, advisories: readonly AdvisoryView[]): BranchRow[] {
  return product.branches.map((branch) => {
    let fixedHere = 0;
    let noFixHere = 0;
    let highestFix: string | null = null;
    for (const advisory of advisories) {
      const affected = advisory.affected.find((a) => a.slug === product.slug);
      if (affected === undefined) {
        continue;
      }
      const fixes = affected.ranges
        .map((r) => r.fixed)
        .filter((f): f is string => f !== null && inBranch(f, branch.name));
      if (fixes.length > 0) {
        fixedHere += 1;
        for (const fix of fixes) {
          if (highestFix === null || (compareDotted(fix, highestFix) ?? 0) > 0) {
            highestFix = fix;
          }
        }
      } else if (affected.ranges.some((r) => spansWithoutFix(r, branch.name))) {
        noFixHere += 1;
      }
    }
    const comparison =
      highestFix !== null && branch.latest !== null
        ? compareDotted(branch.latest, highestFix)
        : null;
    return {
      branch,
      fixedHere,
      highestFix,
      latestCoversFixes: comparison === null ? null : comparison >= 0,
      noFixHere,
    };
  });
}

/**
 * The branch table of a product page: support status, latest release, and how many advisories
 * were fixed inside the branch in the last 12 months. Versions are read with the matcher, so a
 * fix counts for a branch exactly when the matcher places it there.
 */
import type { AdvisoryView, BranchView, ProductView } from './feed.ts';
import { inBranch, isBranch, tryParse } from './match.ts';

export interface BranchRow {
  branch: BranchView;
  /** Advisories published in the last 12 months with a fix released inside this branch. */
  fixedLastYear: number;
}

export interface BranchTable {
  /** Supported branches, then the newest end-of-life branch. */
  shown: BranchRow[];
  /** The older end-of-life branches, folded behind "Show them". */
  older: BranchRow[];
}

const YEAR_MS = 365 * 86_400_000;

export function branchTable(
  product: ProductView,
  advisories: readonly AdvisoryView[],
  now: string | null,
): BranchTable {
  const scheme = product.versionScheme;
  const since = now === null ? null : new Date(Date.parse(now) - YEAR_MS).toISOString();
  const recent = advisories.filter((a) => since === null || a.publishedAt >= since);
  const fixes = recent.map((a) =>
    a.affected
      .filter((x) => x.slug === product.slug)
      .flatMap((x) => x.ranges.flatMap((r) => (r.fixed === null ? [] : [r.fixed])))
      .flatMap((f) => {
        const v = tryParse(scheme, f);
        return v === null ? [] : [v];
      }),
  );
  const rows = product.branches.map((branch) => {
    const b = tryParse(scheme, branch.name);
    const fixedLastYear =
      b === null || !isBranch(b)
        ? 0
        : fixes.filter((list) => list.some((v) => inBranch(v, b))).length;
    return { branch, fixedLastYear };
  });
  const firstEol = rows.findIndex((r) => r.branch.eol);
  const shown = rows.filter((r, i) => !r.branch.eol || i === firstEol);
  const older = rows.filter((r) => !shown.includes(r));
  return { shown, older };
}

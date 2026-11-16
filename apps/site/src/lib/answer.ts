/**
 * The answer block of an advisory page: per affected product, which branches are affected, the
 * release that fixes each one, and what that means for end-of-life branches.
 */
import type { AdvisoryView, AffectedView, ProductView, RangeView } from './feed.ts';
import { compareVersions, inBranch, isBranch, tryParse, type Scheme } from './match.ts';
import { sortVersions } from './releases.ts';

export interface AnswerRow {
  branch: string;
  /** Lead text, then a version in mono (empty when none). */
  affected: { lead: string; version: string; tail: string };
  fixed: string | null;
  eol: boolean;
}

export interface Answer {
  slug: string;
  name: string;
  /** No ranges published: affected versions unknown. */
  unknown: boolean;
  /** Stable fixes, newest branch first; prereleases are listed in the table only. */
  fixes: string[];
  rows: AnswerRow[];
  /** End-of-life branches below the oldest fixed one, which get no fix. */
  eolNote: string | null;
}

function branchIn(product: ProductView | undefined, scheme: Scheme, version: string | null) {
  if (product === undefined || version === null) return undefined;
  const v = tryParse(scheme, version);
  if (v === null) return undefined;
  return product.branches.find((b) => {
    const parsed = tryParse(scheme, b.name);
    return (
      parsed !== null &&
      isBranch(parsed) &&
      (inBranch(v, parsed) || compareVersions(v, parsed) === 0)
    );
  });
}

function rowFor(range: RangeView, product: ProductView | undefined, scheme: Scheme): AnswerRow {
  const end = range.fixed ?? range.lastAffected;
  const branch = branchIn(product, scheme, end) ?? branchIn(product, scheme, range.introduced);
  const fallback = (end ?? range.introduced).replace(/^v/, '').split(/[.-]/);
  let label =
    branch?.name ?? (scheme === 'pg' ? fallback[0] : fallback.slice(0, 2).join('.')) ?? '';
  if (range.introduced === '0') label = `${label} and older`;
  let affected: AnswerRow['affected'];
  const from = range.introduced === '0' ? null : range.introduced;
  if (range.fixed !== null) {
    affected =
      from === null
        ? { lead: 'Every version before', version: range.fixed, tail: '' }
        : { lead: `From ${from}, before`, version: range.fixed, tail: '' };
  } else if (range.lastAffected !== null) {
    affected =
      from === null
        ? { lead: 'Every version up to', version: range.lastAffected, tail: '' }
        : { lead: `From ${from} up to`, version: range.lastAffected, tail: '' };
  } else {
    affected = {
      lead: from === null ? 'Every version' : `From ${from}`,
      version: '',
      tail: ', no fix listed',
    };
  }
  return { branch: label, affected, fixed: range.fixed, eol: branch?.eol === true };
}

export function answers(advisory: AdvisoryView, products: readonly ProductView[]): Answer[] {
  return advisory.affected.map((affected: AffectedView) => {
    const product = products.find((p) => p.slug === affected.slug);
    const scheme: Scheme = product?.versionScheme ?? 'semver';
    const all = affected.ranges.flatMap((r) => (r.fixed === null ? [] : [r.fixed]));
    const stable = all.filter((f) => tryParse(scheme, f)?.pre == null);
    const fixes = sortVersions(scheme, [...new Set(stable.length > 0 ? stable : all)]);
    let eolNote: string | null = null;
    const open = affected.ranges.find((r) => r.introduced === '0' && r.fixed !== null);
    if (product !== undefined && open !== undefined) {
      const fixedBranch = branchIn(product, scheme, open.fixed);
      const index = fixedBranch === undefined ? -1 : product.branches.indexOf(fixedBranch);
      const below = index < 0 ? [] : product.branches.slice(index + 1).filter((b) => b.eol);
      const first = below[0];
      if (first !== undefined) {
        eolNote =
          below.length === 1
            ? `Branch ${first.name} is end of life and gets no fix. Move to a supported branch.`
            : `Branches ${first.name} and older are end of life and get no fix. Move to a supported branch.`;
      }
    }
    return {
      slug: affected.slug,
      name: affected.name,
      unknown: affected.ranges.length === 0,
      fixes,
      rows: affected.ranges.map((r) => rowFor(r, product, scheme)),
      eolNote,
    };
  });
}

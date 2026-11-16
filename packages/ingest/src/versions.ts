import type { VersionRange } from '@advisorydeck/contract';

/** Same rule as defs.schema.json#/$defs/version. */
const VERSION = /^[0-9A-Za-z][0-9A-Za-z.+:~_-]*$/;

/** Words upstream records use for "every version" or "not known yet". */
const ANY = new Set(['*', 'all', 'any', 'n/a', 'unspecified', 'unknown']);
const NONE = new Set(['', 'none', 'tbd', 'n/a', 'unknown', 'unspecified', '-']);

/** Trims a version and drops a leading v (v3.7.18 becomes 3.7.18); undefined when it is not a version. */
export function cleanVersion(raw: string): string | undefined {
  let value = raw.trim();
  if (/^v[0-9]/i.test(value)) value = value.slice(1);
  return VERSION.test(value) && value.length <= 64 ? value : undefined;
}

/** True when the range says which version fixes it or is the last one affected. */
export function isBounded(range: VersionRange): boolean {
  return range.fixed !== undefined || range.last_affected !== undefined;
}

function upper(range: VersionRange, op: string, version: string): VersionRange {
  return op === '<' ? { ...range, fixed: version } : { ...range, last_affected: version };
}

/**
 * Parses a range expression as GHSA and some CVE records write it: `>= 3.0.0, < 3.3.6`,
 * `< 29.9.3`, `<= 25.0.18, 26.0.0 - 29.8.1`, `= 1.2.3`, `All`. A comma joins a lower bound to the
 * upper bound that follows it and otherwise separates ranges. `> X` is read as `>= X` (one version
 * too many rather than one too few). Returns undefined when any part cannot be read, so a caller
 * never publishes half a range.
 */
export function parseRangeExpression(expression: string): VersionRange[] | undefined {
  const trimmed = expression.trim();
  if (ANY.has(trimmed.toLowerCase())) return undefined;
  const ranges: VersionRange[] = [];
  let open: VersionRange | undefined;
  for (const token of trimmed.split(/\s*(?:,|\|\|)\s*/)) {
    if (token === '') continue;
    const hyphen = /^(\S+)\s+-\s+(\S+)$/.exec(token);
    if (hyphen !== null) {
      const from = cleanVersion(hyphen[1] ?? '');
      const to = cleanVersion(hyphen[2] ?? '');
      if (from === undefined || to === undefined) return undefined;
      if (open !== undefined) ranges.push(open);
      open = undefined;
      ranges.push({ introduced: from, last_affected: to });
      continue;
    }
    const match = /^(>=|<=|>|<|==|=)?\s*(\S+)$/.exec(token);
    if (match === null) return undefined;
    const op = match[1] ?? '=';
    const version = cleanVersion(match[2] ?? '');
    if (version === undefined) return undefined;
    if (op === '>=' || op === '>') {
      if (open !== undefined) ranges.push(open);
      open = { introduced: version };
    } else if (op === '<' || op === '<=') {
      // Several upper bounds in a row list one branch each (docker-ce: "<= v19.03.15, <= v20.10.27"):
      // every bound after the first starts at its own major.minor.
      const branch = branchOf(version);
      const start =
        ranges.length > 0 && open === undefined && branch !== undefined
          ? `${branch.major}.${branch.minor}.0`
          : '0';
      ranges.push(upper(open ?? { introduced: start }, op, version));
      open = undefined;
    } else {
      if (open !== undefined) ranges.push(open);
      open = undefined;
      ranges.push({ introduced: version, last_affected: version });
    }
  }
  if (open !== undefined) ranges.push(open);
  return ranges.length > 0 ? ranges : undefined;
}

/** The one version a "patched versions" field names (`29.9.3`, `>= v4.0.0-beta.469`), else undefined. */
export function singlePatchedVersion(raw: string | null | undefined): string | undefined {
  if (raw === null || raw === undefined) return undefined;
  const value = raw.trim();
  if (NONE.has(value.toLowerCase()) || value.includes(',')) return undefined;
  return cleanVersion(value.replace(/^>=\s*/, ''));
}

/** Drops exact duplicates and keeps the first-seen order. */
export function dedupeRanges(ranges: readonly VersionRange[]): VersionRange[] {
  const seen = new Set<string>();
  const out: VersionRange[] = [];
  for (const range of ranges) {
    const key = `${range.introduced}|${range.fixed ?? ''}|${range.last_affected ?? ''}`;
    if (!seen.has(key)) {
      seen.add(key);
      out.push(range);
    }
  }
  return out;
}

const SEMVER_LIKE = /^(\d+)\.(\d+)(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?$/;

/**
 * Orders two semver-like versions (3.6.11, 4.0.0-beta.464), or undefined when either is not one.
 * Only used to spot upstream records whose range and patched version disagree; matching a user's
 * version against ranges is the image's job.
 */
export function compareSemverLike(a: string, b: string): number | undefined {
  const pa = SEMVER_LIKE.exec(a);
  const pb = SEMVER_LIKE.exec(b);
  if (pa === null || pb === null) return undefined;
  for (const i of [1, 2, 3]) {
    const diff = Number(pa[i] ?? 0) - Number(pb[i] ?? 0);
    if (diff !== 0) return Math.sign(diff);
  }
  const ra = pa[4];
  const rb = pb[4];
  if (ra === undefined || rb === undefined) {
    return ra === rb ? 0 : ra === undefined ? 1 : -1;
  }
  const xa = ra.split('.');
  const xb = rb.split('.');
  for (let i = 0; i < Math.max(xa.length, xb.length); i += 1) {
    const sa = xa[i];
    const sb = xb[i];
    if (sa === undefined || sb === undefined) return sa === undefined ? -1 : 1;
    const na = /^\d+$/.test(sa);
    const nb = /^\d+$/.test(sb);
    if (na && nb) {
      const diff = Number(sa) - Number(sb);
      if (diff !== 0) return Math.sign(diff);
    } else if (na !== nb) {
      return na ? -1 : 1;
    } else if (sa !== sb) {
      return sa < sb ? -1 : 1;
    }
  }
  return 0;
}

/** Major and minor of a dotted numeric version (8.2.2 gives 8 and 2), or undefined. */
export function branchOf(version: string): { major: number; minor: number } | undefined {
  const match = /^(\d+)\.(\d+)/.exec(version);
  return match === null ? undefined : { major: Number(match[1]), minor: Number(match[2]) };
}

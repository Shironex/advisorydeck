import type { VersionRange } from '@advisorydeck/contract';

/**
 * defs.schema.json#/$defs/version, narrowed to start with a digit: every scheme ingest reads
 * versions for starts with one, and a word in a version field is a placeholder (Metabase's
 * x.58.0 for "0.58.0 or 1.58.0", NGINX Plus R36), never something a consumer can compare.
 */
const VERSION = /^[0-9][0-9A-Za-z.+:~_-]*$/;

/** Words upstream records use for "every version" or "not known yet". */
const ANY = new Set(['*', 'all', 'any', 'n/a', 'unspecified', 'unknown']);
const NONE = new Set(['', 'none', 'tbd', 'n/a', 'unknown', 'unspecified', '-']);

/**
 * Trims a version and drops a leading v (v3.7.18 becomes 3.7.18); undefined when it is not a
 * version or does not start with a digit. Java release suffixes become semver: a dotted milestone or release candidate is a
 * prerelease (Tomcat 9.0.0.M1 is 9.0.0-M1) and .RELEASE is the release itself (Spring
 * 5.2.25.RELEASE is 5.2.25).
 */
export function cleanVersion(raw: string): string | undefined {
  let value = raw.trim();
  if (/^v[0-9]/i.test(value)) value = value.slice(1);
  value = value
    .replace(/^(\d+\.\d+\.\d+)\.(M|RC)(\d+)$/i, '$1-$2$3')
    .replace(/^(\d+\.\d+\.\d+)\.RELEASE$/i, '$1');
  return VERSION.test(value) && value.length <= 64 ? value : undefined;
}

/**
 * Rewrites PEP 440 prereleases written straight after a version (`3.15.0a1`, `6.0rc2`,
 * `1.2c1`) as semver prereleases (`3.15.0-a1`, `6.0-rc2`, `1.2-rc1`), anywhere in a range
 * expression. Only for Python data (CVE versionType python, the GHSA pip ecosystem): other
 * schemes use the same letters differently (PostgreSQL's 17rc1).
 */
export function pep440Prereleases(text: string): string {
  return text.replace(
    /(^|[^0-9A-Za-z.])(v?\d+(?:\.\d+){0,2})(a|b|rc|c)(\d+)(?![0-9A-Za-z.+-])/g,
    (_, lead: string, version: string, tag: string, n: string) =>
      `${lead}${version}-${tag === 'c' ? 'rc' : tag}${n}`,
  );
}

/** True when the range says which version fixes it or is the last one affected. */
export function isBounded(range: VersionRange): boolean {
  return range.fixed !== undefined || range.last_affected !== undefined;
}

/** Two dotted numeric versions joined by a hyphen with no spaces (`8.4.0-8.4.12`). */
const COMPACT_HYPHEN = /^v?(\d+(?:\.\d+)+)-v?(\d+(?:\.\d+)+)$/;

/**
 * Reads `8.4.0-8.4.12` (Oracle, MariaDB) as a range from the first to the last affected version.
 * Both sides must have the same number of numeric parts, so a real prerelease (`1.2.0-rc.1`,
 * `4.0.0-beta.474`) or a distro revision (`5.15.0-122.132`) is not taken for one. Undefined when
 * the text has another shape; `null` when it has this shape but the first side is later than the
 * second, which no reading can make sense of.
 */
export function compactHyphenRange(raw: string): VersionRange | null | undefined {
  const match = COMPACT_HYPHEN.exec(raw.trim());
  const from = match?.[1];
  const to = match?.[2];
  if (from === undefined || to === undefined) return undefined;
  const a = from.split('.').map(Number);
  const b = to.split('.').map(Number);
  if (a.length !== b.length) return undefined;
  const order = a.reduce((found, n, i) => found || Math.sign(n - (b[i] ?? 0)), 0);
  return order > 0 ? null : { introduced: from, last_affected: to };
}

/** True when a CVE version field holds a range expression rather than one version. */
export function isRangeExpression(raw: string): boolean {
  return /[<>=,]|\s-\s/.test(raw) || compactHyphenRange(raw) !== undefined;
}

function upper(range: VersionRange, op: string, version: string): VersionRange {
  return op === '<' ? { ...range, fixed: version } : { ...range, last_affected: version };
}

/**
 * Parses a range expression as GHSA and some CVE records write it: `>= 3.0.0, < 3.3.6`,
 * `< 29.9.3`, `<= 25.0.18, 26.0.0 - 29.8.1`, `10.6.1-10.6.27`, `= 1.2.3`, `All`. A comma joins a lower bound to the
 * upper bound that follows it and otherwise separates ranges; a space before `<` or `&&` joins them too, and an
 * operator written after its version (`v3.23.0>=`) or swapped (`=>`) is read as if written first. `> X` is read as `>= X` (one version
 * too many rather than one too few). Returns undefined when any part cannot be read, so a caller
 * never publishes half a range.
 */
export function parseRangeExpression(expression: string): VersionRange[] | undefined {
  const trimmed = expression.trim();
  if (ANY.has(trimmed.toLowerCase())) return undefined;
  const ranges: VersionRange[] = [];
  let open: VersionRange | undefined;
  let bare = 0;
  // A space can also join a lower bound to its upper bound (">= 2.0.0 < 2.9.3", npm style).
  for (const written of trimmed.split(/\s*(?:,|\|\||&&)\s*|\s+(?=<)/)) {
    if (written === '') continue;
    const token = operatorFirst(written);
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
    const compact = compactHyphenRange(token);
    if (compact === null) return undefined;
    if (compact !== undefined) {
      if (open !== undefined) ranges.push(open);
      open = undefined;
      ranges.push(compact);
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
      if (open === undefined) bare += 1;
      const start = ranges.length > 0 && open === undefined ? branchStart(op, version) : '0';
      ranges.push(upper(open ?? { introduced: start }, op, version));
      open = undefined;
    } else {
      if (open !== undefined) ranges.push(open);
      open = undefined;
      ranges.push({ introduced: version, last_affected: version });
    }
  }
  if (open !== undefined) ranges.push(open);
  if (ranges.length === 0) return undefined;
  return bare >= 2 && bare === ranges.length ? sortedUpperBounds(ranges) : ranges;
}

/**
 * Puts an operator written after its version, or with its two characters swapped, in front
 * (Ghost: `v3.23.0>=` is `>= v3.23.0`; Valkey: `=>9.0.0` is `>= 9.0.0`).
 */
function operatorFirst(token: string): string {
  const swapped = token.replace(/^=>/, '>=').replace(/^=</, '<=');
  const after = /^(v?[0-9][^\s<>=]*)\s*(>=|<=|>|<)$/.exec(swapped);
  return after === null ? swapped : `${after[2] ?? ''} ${after[1] ?? ''}`;
}

/** The upper bound of a range: its fixed or last affected version. */
function upperOf(range: VersionRange): string {
  return range.fixed ?? range.last_affected ?? '';
}

/**
 * An expression made only of upper bounds lists one branch each, in any order (Valkey writes
 * `<= 9.1.1, <= 9.0.5, <= 8.1.9, <= 8.0.10`, newest first). Sorted, the lowest starts at 0 and
 * every other one at its own major.minor, so the newest bound does not swallow the patched
 * releases of the older branches. Left in the written order when two bounds cannot be ordered.
 */
function sortedUpperBounds(ranges: readonly VersionRange[]): VersionRange[] {
  const bounds = ranges.map(upperOf);
  if (bounds.some((b) => compareSemverLike(b, b) === undefined)) return [...ranges];
  const sorted = [...ranges].sort((a, b) => compareSemverLike(upperOf(a), upperOf(b)) ?? 0);
  return sorted.map((range, i) => ({
    ...range,
    introduced: i === 0 ? '0' : branchStart(range.fixed === undefined ? '<=' : '<', upperOf(range)),
  }));
}

/**
 * Where a listed upper bound's branch starts: its major.minor.0, or the lowest prerelease of it
 * (`1.5.0-0`) when the bound is a prerelease of that first release (runc: `<= 1.5.0-rc.2`), which
 * would otherwise give an empty range and miss the release candidates. `0` when the bound has no
 * major.minor.
 */
function branchStart(op: string, bound: string): string {
  const branch = branchOf(bound);
  if (branch === undefined) return '0';
  const start = `${branch.major}.${branch.minor}.0`;
  const order = compareSemverLike(start, bound) ?? 0;
  return (op === '<' ? order >= 0 : order > 0) ? `${start}-0` : start;
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

/**
 * Several ranges that each start at 0 and end at a bound on its own branch (`< 1.123.96`,
 * `< 2.47.6`, `< 2.48.3`, `< 3.2.2`, written as separate entries) list one fix per branch. Read
 * together they would cover every patched release below the highest bound, so they are sorted and
 * each later range starts where the previous bound's line ends: on the next minor within one
 * major (`2.48.0` after `2.47.6`), on the next major across majors (`2.0.0` after `1.123.96`,
 * `3.0.0` after `2.48.3`). An unlisted line between two listed ones of a major (Keycloak 26.5)
 * and a whole unlisted major (Node.js 23) stay affected up to the next listed fix, the stricter
 * reading for an end of life line that never got the patch; minors after the last listed line of
 * a major are later releases of it, which carry the fix. When a bound is the first release or a
 * prerelease of the line the range starts on, the start is that release's lowest prerelease
 * (`8.8.0-0`), so release candidates stay covered. Undefined when the shape does not fit: fewer than two ranges, a lower
 * bound other than 0, an open range, two bounds on one branch or a bound that is not semver-like.
 */
export function perBranchUpperBounds(ranges: readonly VersionRange[]): VersionRange[] | undefined {
  if (ranges.length < 2 || !ranges.every((r) => r.introduced === '0' && isBounded(r))) {
    return undefined;
  }
  const branches = new Set<string>();
  for (const range of ranges) {
    const branch = branchOf(upperOf(range));
    if (branch === undefined || compareSemverLike(upperOf(range), upperOf(range)) === undefined) {
      return undefined;
    }
    branches.add(`${branch.major}.${branch.minor}`);
  }
  if (branches.size !== ranges.length) return undefined;
  const sorted = [...ranges].sort((a, b) => compareSemverLike(upperOf(a), upperOf(b)) ?? 0);
  return sorted.map((range, i) => {
    const previous = i === 0 ? undefined : branchOf(upperOf(sorted[i - 1] ?? range));
    const current = branchOf(upperOf(range));
    if (previous === undefined || current === undefined) return range;
    const start =
      previous.major === current.major
        ? `${previous.major}.${previous.minor + 1}.0`
        : `${previous.major + 1}.0.0`;
    const order = compareSemverLike(start, upperOf(range)) ?? 0;
    const empty = range.fixed !== undefined ? order >= 0 : order > 0;
    return { ...range, introduced: empty ? `${start}-0` : start };
  });
}

/** A lower bound written with one or two numeric parts (`14`, `13.3`) as a full version. */
function fullVersion(version: string): string {
  if (/^\d+$/.test(version)) return `${version}.0.0`;
  if (/^\d+\.\d+$/.test(version)) return `${version}.0`;
  return version;
}

/**
 * Pairs open lower bounds with a patched list (Nextcloud: `>= 32.0.0, >= 33.0.0, >= 34.0.0`
 * patched `32.0.12, 33.0.6, 34.0.1`). Both sorted, each fix belongs to the last lower bound at or
 * below it. A lower bound with several fixes lists one per branch (Next.js: `>= 15` patched
 * `15.0.7, 15.1.11, ...`): the first range starts at the lower bound, each next one at its own
 * line (x.y.0 within a major, x.0.0 across majors, the lowest prerelease when the fix is a
 * prerelease of that line, `15.6.0-canary.60`). A lower bound with no fix is affected up to the
 * next lower bound when that one starts a line (`>= 13.3` before `>= 14` is every 13 release), and
 * stays open when it is the last. Lower bounds of one or two parts are written in full
 * (`14.0.0`). Undefined when the pairing is not clear: a fix below every lower bound, two fixes on
 * one branch, a version that cannot be ordered, or an unfixed bound before one that does not start
 * a line.
 */
export function pairLowerBounds(
  lowers: readonly VersionRange[],
  fixes: readonly string[] | undefined,
): VersionRange[] | undefined {
  if (fixes === undefined || lowers.some(isBounded)) return undefined;
  const starts = lowers.map((r) => fullVersion(r.introduced));
  const all = [...starts, ...fixes];
  if (all.some((v) => compareSemverLike(v, v) === undefined)) return undefined;
  starts.sort((a, b) => compareSemverLike(a, b) ?? 0);
  const groups: string[][] = starts.map(() => []);
  for (const fixed of fixes) {
    const at = starts.findLastIndex((s) => (compareSemverLike(fixed, s) ?? 0) > 0);
    if (at < 0) return undefined;
    groups[at]?.push(fixed);
  }
  const paired: VersionRange[] = [];
  for (const [i, introduced] of starts.entries()) {
    const own = groups[i] ?? [];
    if (own.length === 0) {
      const next = starts[i + 1];
      if (next === undefined) {
        paired.push({ introduced });
        continue;
      }
      const line = /^(\d+)\.(\d+)\.0$/.exec(next);
      if (line === null) return undefined;
      const minor = Number(line[2]);
      paired.push({
        introduced,
        last_affected: minor > 0 ? `${line[1] ?? ''}.${minor - 1}` : `${Number(line[1]) - 1}`,
      });
      continue;
    }
    const branches = new Set(own.map((f) => `${branchOf(f)?.major}.${branchOf(f)?.minor}`));
    if (branches.size !== own.length) return undefined;
    for (const [j, fixed] of own.entries()) {
      if (j === 0) {
        paired.push({ introduced, fixed });
        continue;
      }
      const previous = branchOf(own[j - 1] ?? '');
      const current = branchOf(fixed);
      if (previous === undefined || current === undefined) return undefined;
      const line =
        previous.major === current.major
          ? `${current.major}.${current.minor}.0`
          : `${current.major}.0.0`;
      const order = compareSemverLike(line, fixed) ?? 0;
      paired.push({ introduced: order >= 0 ? `${line}-0` : line, fixed });
    }
  }
  return paired;
}

/**
 * Ends an open range where the next listed line starts (F5 for nginx: `1.31.0 < 1.31.7`,
 * `1.30.0 < 1.30.6`, `1.25.0 < *`). Left open, the range from 1.25.0 would also cover the patched
 * 1.30.6 and 1.31.7, which the same record lists as fixed. It is clipped to the branch before the
 * next listed start (`last_affected: "1.29"`, every release of 1.29), which only works where a
 * two-part version names a branch, so callers use it for semver products only. A range is left
 * open when no later start is listed, a later line has no fix either, or the later start is not
 * the first release of a line.
 */
export function clipOpenRanges(ranges: readonly VersionRange[]): VersionRange[] {
  return ranges.map((range) => {
    if (isBounded(range)) return range;
    const above = (start: string) =>
      range.introduced === '0'
        ? start !== '0'
        : (compareSemverLike(start, range.introduced) ?? 0) > 0;
    const after = ranges.filter((r) => above(r.introduced));
    // A later line without a fix keeps everything above it affected anyway.
    if (!after.every(isBounded)) return range;
    const later = after.map((r) => r.introduced).sort((a, b) => compareSemverLike(a, b) ?? 0)[0];
    const next = /^(\d+)\.(\d+)\.0$/.exec(later ?? '');
    const from = range.introduced === '0' ? { major: 0, minor: 0 } : branchOf(range.introduced);
    if (next === null || from === undefined) return range;
    const major = Number(next[1]);
    const minor = Number(next[2]);
    if (minor > 0 && (from.major < major || (from.major === major && from.minor < minor))) {
      return { ...range, last_affected: `${major}.${minor - 1}` };
    }
    if (minor === 0 && major > 0 && from.major < major) {
      return { ...range, last_affected: `${major - 1}` };
    }
    return range;
  });
}

/** compareSemverLike after dropping build metadata (1.34.5+k3s1 orders as 1.34.5). */
function compareIgnoringBuild(a: string, b: string): number | undefined {
  return compareSemverLike(a.replace(/\+.*$/, ''), b.replace(/\+.*$/, ''));
}

/**
 * Takes the patched rest of each listed line out of a wider range of the same record. Records
 * often write one range across all lines next to one range per older line (`< 8.8.0`, `< 8.7.2`,
 * `< 8.6.2` for Rocket.Chat; `7.1.0` patched 7.1.1 next to `7.0.0 - 7.0.4` patched 7.0.5 for
 * WordPress; `2.0.0 - 2.7.0` next to `2.6.0 - 2.6.3` for OpenBao). Read literally, the wide range
 * covers the releases the narrower ones name as fixed (8.7.2, 7.0.5, 2.6.4). So when a range ends
 * on one line and a wider range of the same record runs past that line, the wide range skips from
 * the narrow range's end to the start of the next line (`8.7.2` up to `8.8.0`). The next line
 * starts at its lowest prerelease (`8.8.0-0`) when the wide range ends on that line's first
 * release or a prerelease of it, so release candidates stay covered. Unlisted lines in between and
 * releases below every listed line stay affected. Ranges whose bounds are not semver-like are left
 * as they are, and so is a wide range that ends on the narrow range's own line (the stricter
 * reading inside one line).
 */
export function exceptPatchedLines(ranges: readonly VersionRange[]): VersionRange[] {
  const endOf = (r: VersionRange) => r.fixed ?? r.last_affected;
  const narrow = ranges.filter((r) => {
    const end = endOf(r);
    return end !== undefined && compareIgnoringBuild(end, end) !== undefined;
  });
  if (ranges.length < 2 || narrow.length === 0) return [...ranges];
  let pieces: VersionRange[] = [...ranges];
  for (const b of narrow) {
    const end = endOf(b) ?? '';
    const line = branchOf(end);
    if (line === undefined) continue;
    const next = `${line.major}.${line.minor + 1}.0`;
    const out: VersionRange[] = [];
    for (const a of pieces) {
      if (a === b) {
        out.push(a);
        continue;
      }
      const aEnd = endOf(a);
      const startsBefore =
        a.introduced === '0' || (compareIgnoringBuild(a.introduced, end) ?? 1) <= 0;
      // The wide range must reach past the narrow range's line.
      const pastLine =
        aEnd === undefined ||
        (compareIgnoringBuild(aEnd, `${line.major}.${line.minor + 1}.0-0`) ?? -1) >= 0;
      const coversFix =
        b.fixed !== undefined || aEnd === undefined || (compareIgnoringBuild(aEnd, end) ?? 0) > 0;
      if (!startsBefore || !pastLine || !coversFix) {
        out.push(a);
        continue;
      }
      // Below: from the wide range's start up to the narrow range's end.
      out.push(
        b.fixed !== undefined
          ? { introduced: a.introduced, fixed: b.fixed }
          : { introduced: a.introduced, last_affected: end },
      );
      // Above: from the next line on.
      const lowest =
        aEnd !== undefined &&
        (a.fixed !== undefined
          ? (compareIgnoringBuild(next, aEnd) ?? 0) >= 0
          : (compareIgnoringBuild(next, aEnd) ?? 0) > 0);
      out.push({ ...a, introduced: lowest ? `${next}-0` : next });
    }
    pieces = out;
  }
  return dedupeRanges(pieces);
}

/** Major and minor of a dotted numeric version (8.2.2 gives 8 and 2), or undefined. */
export function branchOf(version: string): { major: number; minor: number } | undefined {
  const match = /^(\d+)\.(\d+)/.exec(version);
  return match === null ? undefined : { major: Number(match[1]), minor: Number(match[2]) };
}

/** A stretch of versions: from lo (inclusive, `0` is the first version) to hi, or open above. */
export interface Span {
  lo: string;
  hi?: string;
  /** True when hi itself is inside the span. */
  hiIncluded: boolean;
}

/** Orders two bounds, `0` before every version; undefined when either is not semver-like. */
function compareBound(a: string, b: string): number | undefined {
  if (a === '0' || b === '0') return a === b ? 0 : a === '0' ? -1 : 1;
  return compareSemverLike(a, b);
}

/** The first release of the line after a version's major.minor (10.11.21 gives 10.12.0). */
export function nextLine(version: string): string | undefined {
  const branch = branchOf(version);
  return branch === undefined ? undefined : `${branch.major}.${branch.minor + 1}.0`;
}

/** The span a range covers. */
export function spanOf(range: VersionRange): Span {
  const hi = range.fixed ?? range.last_affected;
  return hi === undefined
    ? { lo: range.introduced, hiIncluded: false }
    : { lo: range.introduced, hi, hiIncluded: range.last_affected !== undefined };
}

/** -1, 0 or 1 for two upper ends, open above sorting last; undefined when they cannot be ordered. */
function compareHigh(a: Span, b: Span): number | undefined {
  if (a.hi === undefined || b.hi === undefined) {
    return a.hi === b.hi ? 0 : a.hi === undefined ? 1 : -1;
  }
  const order = compareBound(a.hi, b.hi);
  if (order !== 0) return order;
  return a.hiIncluded === b.hiIncluded ? 0 : a.hiIncluded ? 1 : -1;
}

/** True when a version is below a span's upper end, or at it when that end is included. */
function belowHigh(version: string, span: Span): boolean | undefined {
  if (span.hi === undefined) return true;
  const order = compareBound(version, span.hi);
  if (order === undefined) return undefined;
  return span.hiIncluded ? order <= 0 : order < 0;
}

/** True when two spans share a version; undefined when their bounds cannot be ordered. */
export function spansOverlap(a: Span, b: Span): boolean | undefined {
  const x = belowHigh(b.lo, a);
  const y = belowHigh(a.lo, b);
  return x === undefined || y === undefined ? undefined : x && y;
}

/**
 * Removes unaffected spans from affected ranges, for records that list both and where an
 * unaffected version lies inside an affected range (Mattermost: `0 <= 10.20.11` affected with
 * 10.11.21 unaffected) or that only list what is unaffected (Jenkins, default status affected).
 * The affected ranges are joined first, so overlapping ranges from 0 become one stretch, and
 * every unaffected span cuts it. Undefined when any bound cannot be ordered, or when a cut ends
 * on an included version (what follows it cannot be written as a range start): a guess there
 * could read a vulnerable release as not affected.
 */
export function subtractSpans(
  affected: readonly VersionRange[],
  unaffected: readonly Span[],
): VersionRange[] | undefined {
  const spans = affected.map(spanOf);
  if (spans.some((s) => compareBound(s.lo, s.lo) === undefined)) return undefined;
  // Every start is semver-like (checked above), so any two of them can be ordered.
  const byStart = [...spans].sort((a, b) => compareBound(a.lo, b.lo) ?? 0);
  const joined: Span[] = [];
  for (const span of byStart) {
    const last = joined.at(-1);
    const start = last?.hi === undefined ? -1 : compareBound(span.lo, last.hi);
    if (start === undefined) return undefined;
    if (last === undefined || start > 0) {
      joined.push({ ...span });
      continue;
    }
    const order = compareHigh(span, last);
    if (order === undefined) return undefined;
    if (order > 0) joined[joined.length - 1] = { ...span, lo: last.lo };
  }
  let pieces = joined;
  for (const cut of unaffected) {
    const next: Span[] = [];
    for (const piece of pieces) {
      const overlap = spansOverlap(piece, cut);
      if (overlap === undefined) return undefined;
      if (!overlap) {
        next.push(piece);
        continue;
      }
      if ((compareBound(piece.lo, cut.lo) ?? 0) < 0) {
        next.push({ lo: piece.lo, hi: cut.lo, hiIncluded: false });
      }
      if (cut.hi === undefined) continue;
      const rest = belowHigh(cut.hi, piece);
      if (rest === undefined) return undefined;
      const exactEnd =
        piece.hi !== undefined && piece.hiIncluded && compareBound(cut.hi, piece.hi) === 0;
      if (!rest || (cut.hiIncluded && exactEnd)) continue;
      if (cut.hiIncluded) return undefined;
      next.push({
        lo: cut.hi,
        ...(piece.hi === undefined ? {} : { hi: piece.hi }),
        hiIncluded: piece.hiIncluded,
      });
    }
    pieces = next;
  }
  return pieces.map((p) =>
    p.hi === undefined
      ? { introduced: p.lo }
      : p.hiIncluded
        ? { introduced: p.lo, last_affected: p.hi }
        : { introduced: p.lo, fixed: p.hi },
  );
}

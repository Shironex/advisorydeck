/**
 * The version matcher of the notifier image (image/internal/match), in TypeScript, so the
 * product page can answer "is my version affected" in the browser with the same rules. It runs
 * the same vectors as the Go package (fixtures/match, see test/match.test.ts). Pure: no I/O.
 *
 * Every answer is affected, not affected, or unknown with a reason. An advisory without ranges
 * is unknown and a version that cannot be read is unknown: it never answers "not affected" by
 * default.
 */

export type Scheme = 'semver' | 'semver4' | 'pg' | 'calver' | 'dpkg' | 'kernel' | 'opaque';
export type Outcome = 'affected' | 'not-affected' | 'unknown';
export type Reason =
  | 'in-range'
  | 'branch-in-range'
  | 'outside-ranges'
  | 'no-ranges'
  | 'product-not-listed'
  | 'unparseable-version'
  | 'unparseable-range'
  | 'floating-tag'
  | 'not-comparable';

/** A range as the feed publishes it (schemas/v1/defs.schema.json#/$defs/range). */
export interface MatchRange {
  introduced: string;
  fixed?: string | null | undefined;
  last_affected?: string | null | undefined;
}

export interface MatchAdvisory {
  id: string;
  affected: { product: string; ranges: MatchRange[] }[];
}

export interface MatchResult {
  outcome: Outcome;
  reason: Reason;
  /** One line for people, without markup. */
  detail: string;
  /** The range that decided an affected outcome. */
  range: MatchRange | null;
  /** The fixed version of that range, empty when it has none. */
  fixedIn: string;
  /** The installed value was a branch, so the answer covers every release of it. */
  branch: boolean;
}

const MAX_VERSION_LEN = 64;
const MAX_UINT64 = 18446744073709551615n;

interface Deb {
  epoch: bigint;
  upstream: string;
  revision: string;
}

export interface Version {
  scheme: Scheme;
  raw: string;
  nums: bigint[];
  pre: string[] | null;
  /** Significant components when the version names a branch (17 in pg); 0 for a release. */
  depth: number;
  /** A synthetic bound just below every version sharing nums; only range evaluation makes it. */
  floor: boolean;
  deb: Deb;
}

export class VersionError extends Error {}

const isDigit = (c: string): boolean => c >= '0' && c <= '9';
const isLetter = (c: string): boolean => (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
const isDigits = (s: string): boolean => /^[0-9]+$/.test(s);
const cmp = <T extends number | bigint | string>(a: T, b: T): number =>
  a < b ? -1 : a > b ? 1 : 0;

function parseUint(s: string): bigint {
  if (!isDigits(s)) {
    throw new VersionError(`component "${s}" is not a number`);
  }
  const n = BigInt(s);
  if (n > MAX_UINT64) {
    throw new VersionError(`component "${s}" is too large`);
  }
  return n;
}

function parseNums(s: string, minParts: number, maxParts: number): bigint[] {
  const parts = s.split('.');
  if (parts.length < minParts || parts.length > maxParts) {
    throw new VersionError(
      `want ${minParts} to ${maxParts} numeric components, got ${parts.length}`,
    );
  }
  return parts.map(parseUint);
}

function pad(nums: bigint[], n: number): bigint[] {
  const out = [...nums];
  while (out.length < n) {
    out.push(0n);
  }
  return out;
}

function parsePre(s: string): string[] {
  const ids = s.split('.');
  for (const id of ids) {
    if (id === '') {
      throw new VersionError('empty prerelease identifier');
    }
    for (const c of id) {
      if (!isDigit(c) && !isLetter(c) && c !== '-') {
        throw new VersionError(`prerelease identifier "${id}" has "${c}"`);
      }
    }
  }
  return ids;
}

const NO_DEB: Deb = { epoch: 0n, upstream: '', revision: '' };

function base(scheme: Scheme, raw: string): Version {
  return { scheme, raw, nums: [], pre: null, depth: 0, floor: false, deb: NO_DEB };
}

/**
 * Reads a semver version with up to width numeric components (3, or 4 for semver4: Nextcloud
 * Enterprise 31.0.14.7, a missing fourth component being 0); one or two components without a
 * prerelease name a branch.
 */
function parseSemver(input: string, scheme: 'semver' | 'semver4', width: number): Version {
  let s = input;
  if (s.startsWith('v') || s.startsWith('V')) {
    s = s.slice(1);
  }
  const raw = s;
  const plus = s.indexOf('+');
  if (plus >= 0) {
    parsePre(s.slice(plus + 1));
    s = s.slice(0, plus);
  }
  const dash = s.indexOf('-');
  let core = dash >= 0 ? s.slice(0, dash) : s;
  let preText = dash >= 0 ? s.slice(dash + 1) : null;
  if (preText === null) {
    [core, preText] = cutPEP440(core);
  }
  const nums = parseNums(core, 1, width);
  const v = base(scheme, raw);
  if (preText !== null) {
    v.pre = parsePre(preText);
  } else if (nums.length < 3) {
    v.depth = nums.length;
  }
  v.nums = pad(nums, width);
  return v;
}

/**
 * Splits a PEP 440 prerelease written straight after the version (3.14.0rc1, 6.0a1, 3.15.0b2)
 * into the version and the prerelease, so it compares like the semver prerelease 3.14.0-rc1.
 * Anything else is returned whole, to fail as before.
 */
function cutPEP440(s: string): [string, string | null] {
  const i = s.search(/[^0-9.]/);
  if (i <= 0 || !isDigit(s.charAt(i - 1))) {
    return [s, null];
  }
  const tag = s.slice(i);
  for (const kind of ['rc', 'a', 'b']) {
    if (tag.startsWith(kind) && isDigits(tag.slice(kind.length))) {
      return [s.slice(0, i), tag];
    }
  }
  return [s, null];
}

function splitPGPre(s: string): [string, string[] | null] {
  for (const tag of ['alpha', 'beta', 'rc']) {
    const i = s.indexOf(tag);
    if (i < 0) {
      continue;
    }
    const n = s.slice(i + tag.length);
    if (!isDigits(n)) {
      throw new VersionError(`prerelease "${s.slice(i)}" needs a number`);
    }
    return [s.slice(0, i), [tag, n]];
  }
  return [s, null];
}

function parsePG(s: string): Version {
  const [core, pre] = splitPGPre(s);
  const nums = parseNums(core, 1, 3);
  // Since 10 a release is major.minor; before, major.minor.patch.
  const width = (nums[0] ?? 0n) >= 10n ? 2 : 3;
  if (nums.length > width) {
    throw new VersionError(`PostgreSQL ${nums[0]} has at most ${width} components`);
  }
  const v = base('pg', s);
  v.pre = pre;
  if (pre === null && nums.length < width) {
    v.depth = nums.length;
  }
  v.nums = pad(nums, width);
  return v;
}

function parseCalver(s: string): Version {
  const dash = s.indexOf('-');
  const v = base('calver', s);
  v.nums = parseNums(dash >= 0 ? s.slice(0, dash) : s, 1, 6);
  if (dash >= 0) {
    v.pre = parsePre(s.slice(dash + 1));
  }
  return v;
}

function parseKernel(s: string): Version {
  const dash = s.indexOf('-');
  const v = base('kernel', s);
  v.nums = pad(parseNums(dash >= 0 ? s.slice(0, dash) : s, 2, 3), 3);
  if (dash >= 0) {
    const rc = s.slice(dash + 1);
    const n = rc.startsWith('rc') ? rc.slice(2) : '';
    if (!isDigits(n)) {
      throw new VersionError(
        `suffix "${rc}" is not an upstream -rcN; distro kernels need a distro notice`,
      );
    }
    v.pre = ['rc', n];
  }
  return v;
}

function checkDebChars(s: string, extra: string): void {
  for (const c of s) {
    if (!isDigit(c) && !isLetter(c) && !extra.includes(c)) {
      throw new VersionError(`character "${c}" is not allowed`);
    }
  }
}

function parseDpkg(s: string): Version {
  let epoch = 0n;
  let rest = s;
  const colon = s.indexOf(':');
  if (colon >= 0) {
    epoch = parseUint(s.slice(0, colon));
    rest = s.slice(colon + 1);
  }
  let upstream = rest;
  let revision = '';
  const dash = rest.lastIndexOf('-');
  if (dash >= 0) {
    upstream = rest.slice(0, dash);
    revision = rest.slice(dash + 1);
    if (revision === '') {
      throw new VersionError('empty revision after the last hyphen');
    }
  }
  if (upstream === '' || !isDigit(upstream.charAt(0))) {
    throw new VersionError('upstream version must start with a digit');
  }
  checkDebChars(upstream, '.+~-:');
  checkDebChars(revision, '.+~');
  const v = base('dpkg', s);
  v.deb = { epoch, upstream, revision };
  return v;
}

function parseOpaque(s: string): Version {
  for (const c of s) {
    const code = c.charCodeAt(0);
    if (code <= 0x20 || code >= 0x7f) {
      throw new VersionError(`byte ${code} is not printable ASCII`);
    }
  }
  return base('opaque', s);
}

const PARSERS: Record<Scheme, (s: string) => Version> = {
  semver: (s) => parseSemver(s, 'semver', 3),
  semver4: (s) => parseSemver(s, 'semver4', 4),
  pg: parsePG,
  calver: parseCalver,
  dpkg: parseDpkg,
  kernel: parseKernel,
  opaque: parseOpaque,
};

export function isScheme(value: string): value is Scheme {
  return Object.hasOwn(PARSERS, value);
}

/** Reads s in the scheme; throws VersionError when it cannot. */
export function parseVersion(scheme: Scheme, s: string): Version {
  if (s.length === 0 || s.length > MAX_VERSION_LEN) {
    throw new VersionError(`"${s}": length must be 1 to ${MAX_VERSION_LEN}`);
  }
  const parser = PARSERS[scheme] as ((s: string) => Version) | undefined;
  if (parser === undefined) {
    throw new VersionError(`unknown version scheme "${scheme}"`);
  }
  try {
    return parser(s);
  } catch (error) {
    const why = error instanceof Error ? error.message : String(error);
    throw new VersionError(`invalid version "${s}" (${scheme}): ${why}`);
  }
}

/** Parses, or returns null when s is not a version of the scheme. */
export function tryParse(scheme: Scheme, s: string): Version | null {
  try {
    return parseVersion(scheme, s);
  } catch {
    return null;
  }
}

export const isBranch = (v: Version): boolean => v.depth > 0;

function splitRun(s: string): [string, string] {
  const digit = isDigit(s.charAt(0));
  let i = 1;
  while (i < s.length && isDigit(s.charAt(i)) === digit) {
    i += 1;
  }
  return [s.slice(0, i), s.slice(i)];
}

function compareDigitRuns(a: string, b: string): number {
  const x = a.replace(/^0+/, '');
  const y = b.replace(/^0+/, '');
  if (x.length !== y.length) {
    return cmp(x.length, y.length);
  }
  return cmp(x, y);
}

function compareNatural(left: string, right: string): number {
  let a = left;
  let b = right;
  while (a !== '' && b !== '') {
    const [ra, restA] = splitRun(a);
    const [rb, restB] = splitRun(b);
    const da = isDigits(ra);
    const db = isDigits(rb);
    let c: number;
    if (da && db) {
      c = compareDigitRuns(ra, rb);
    } else if (da) {
      c = -1;
    } else if (db) {
      c = 1;
    } else {
      c = cmp(ra, rb);
    }
    if (c !== 0) {
      return c;
    }
    a = restA;
    b = restB;
  }
  return cmp(a.length, b.length);
}

function compareIdent(a: string, b: string): number {
  const aNum = isDigits(a);
  const bNum = isDigits(b);
  if (aNum && bNum) return compareDigitRuns(a, b);
  if (aNum) return -1;
  if (bNum) return 1;
  return compareNatural(a, b);
}

function comparePre(a: string[] | null, b: string[] | null): number {
  if (a === null && b === null) return 0;
  if (a === null) return 1;
  if (b === null) return -1;
  for (let i = 0; i < a.length && i < b.length; i += 1) {
    const c = compareIdent(a[i] ?? '', b[i] ?? '');
    if (c !== 0) {
      return c;
    }
  }
  return cmp(a.length, b.length);
}

function compareNumeric(a: Version, b: Version): number {
  const n = Math.max(a.nums.length, b.nums.length);
  for (let i = 0; i < n; i += 1) {
    const c = cmp(a.nums[i] ?? 0n, b.nums[i] ?? 0n);
    if (c !== 0) {
      return c;
    }
  }
  if (a.floor || b.floor) {
    if (a.floor && b.floor) return 0;
    return a.floor ? -1 : 1;
  }
  return comparePre(a.pre, b.pre);
}

/** dpkg sort weight of one character in a non-digit run. */
function debOrder(s: string, i: number): number {
  if (i >= s.length) return 0;
  const c = s.charAt(i);
  if (isDigit(c)) return 0;
  if (isLetter(c)) return c.charCodeAt(0);
  if (c === '~') return -1;
  return c.charCodeAt(0) + 256;
}

function verrevcmp(a: string, b: string): number {
  let i = 0;
  let j = 0;
  while (i < a.length || j < b.length) {
    while ((i < a.length && !isDigit(a.charAt(i))) || (j < b.length && !isDigit(b.charAt(j)))) {
      const ac = debOrder(a, i);
      const bc = debOrder(b, j);
      if (ac !== bc) {
        return cmp(ac, bc);
      }
      i += 1;
      j += 1;
    }
    const si = i;
    while (i < a.length && isDigit(a.charAt(i))) i += 1;
    const sj = j;
    while (j < b.length && isDigit(b.charAt(j))) j += 1;
    const c = compareDigitRuns(a.slice(si, i), b.slice(sj, j));
    if (c !== 0) {
      return c;
    }
  }
  return 0;
}

function compareDeb(a: Deb, b: Deb): number {
  if (a.epoch !== b.epoch) {
    return cmp(a.epoch, b.epoch);
  }
  return verrevcmp(a.upstream, b.upstream) || verrevcmp(a.revision, b.revision);
}

/** Orders two versions of one scheme: -1, 0 or 1. A branch compares as its first release. */
export function compareVersions(a: Version, b: Version): number {
  if (a.scheme !== b.scheme) {
    return cmp(a.scheme + a.raw, b.scheme + b.raw);
  }
  if (a.scheme === 'dpkg') return compareDeb(a.deb, b.deb);
  if (a.scheme === 'opaque') return cmp(a.raw, b.raw);
  return compareNumeric(a, b);
}

/** The first release of a branch (17 -> 17.0), with no prerelease. */
function branchLow(v: Version): Version {
  return { ...v, depth: 0 };
}

/** The lowest version a range bound covers; a branch bound sits below its prereleases. */
function rangeLow(v: Version): Version {
  return v.depth === 0 ? v : { ...v, depth: 0, floor: true };
}

function releaseCeil(v: Version): Version {
  return { ...v, floor: false, pre: null };
}

/** The exclusive end of a branch: the floor of the next branch (17 -> below 18beta1). */
function branchHigh(v: Version): Version {
  const nums = [...v.nums];
  nums[v.depth - 1] = (nums[v.depth - 1] ?? 0n) + 1n;
  for (let i = v.depth; i < nums.length; i += 1) {
    nums[i] = 0n;
  }
  return { ...v, nums, depth: 0, floor: true, pre: null };
}

/** Whether release v belongs to branch b (17.4 to 17, 3.7.18 to 3.7). */
export function inBranch(v: Version, b: Version): boolean {
  if (!isBranch(b) || v.scheme !== b.scheme || v.scheme === 'opaque' || v.scheme === 'dpkg') {
    return false;
  }
  return compareVersions(v, rangeLow(b)) >= 0 && compareVersions(v, branchHigh(b)) < 0;
}

interface Bounds {
  low: Version | null;
  fixed: Version | null;
  last: Version | null;
}

function readBounds(scheme: Scheme, r: MatchRange): Bounds {
  const fixed = r.fixed ?? '';
  const last = r.last_affected ?? '';
  if (fixed !== '' && last !== '') {
    throw new VersionError(`range from "${r.introduced}" has both fixed and last_affected`);
  }
  const read = (field: string, value: string): Version => {
    try {
      return parseVersion(scheme, value);
    } catch (error) {
      throw new VersionError(`${field}: ${error instanceof Error ? error.message : ''}`);
    }
  };
  return {
    low: r.introduced === '0' ? null : read('introduced', r.introduced),
    fixed: fixed === '' ? null : read('fixed', fixed),
    last: last === '' ? null : read('last_affected', last),
  };
}

function below(b: Bounds, x: Version): boolean {
  if (b.fixed !== null) return compareVersions(x, rangeLow(b.fixed)) < 0;
  if (b.last !== null && isBranch(b.last)) return compareVersions(x, branchHigh(b.last)) < 0;
  if (b.last !== null) return compareVersions(x, b.last) <= 0;
  return true;
}

function contains(b: Bounds, x: Version): boolean {
  if (b.low !== null && compareVersions(x, rangeLow(b.low)) < 0) {
    return false;
  }
  return below(b, x);
}

/** Whether any release of branch br is inside the range; prerelease-only ranges never hit. */
function intersectsBranch(b: Bounds, br: Version): boolean {
  let start = branchLow(br);
  const hi = branchHigh(br);
  if (b.low !== null) {
    const l = releaseCeil(rangeLow(b.low));
    if (compareVersions(l, start) > 0) {
      start = l;
    }
  }
  if (compareVersions(start, hi) >= 0) {
    return false;
  }
  return below(b, start);
}

function unknown(reason: Reason, detail: string, branch = false): MatchResult {
  return { outcome: 'unknown', reason, detail, range: null, fixedIn: '', branch };
}

function affected(v: Version, r: MatchRange): MatchResult {
  const fixed = r.fixed ?? '';
  const branch = isBranch(v);
  let detail: string;
  if (branch && fixed !== '') {
    detail = `branch ${v.raw} is affected before ${fixed}; if you run a floating tag, pull again and recreate the container, or upgrade to ${fixed} or later`;
  } else if (branch) {
    detail = `branch ${v.raw} is affected and the advisory names no fixed release`;
  } else if (fixed !== '') {
    detail = `${v.raw} is affected; fixed in ${fixed}`;
  } else {
    detail = `${v.raw} is affected and the advisory names no fixed release`;
  }
  return {
    outcome: 'affected',
    reason: branch ? 'branch-in-range' : 'in-range',
    detail,
    range: r,
    fixedIn: fixed,
    branch,
  };
}

function evaluateOpaque(v: Version, ranges: readonly MatchRange[]): MatchResult {
  for (const r of ranges) {
    if (r.introduced === v.raw || r.last_affected === v.raw) {
      return affected(v, r);
    }
  }
  return unknown(
    'not-comparable',
    `versions of this product cannot be ordered and ${v.raw} is not named in the advisory; check manually`,
  );
}

const NO_RANGES = 'the advisory does not say which versions are affected; check manually';

/** Evaluates a parsed branch or exact version against one product's ranges. */
export function evaluateVersion(v: Version, ranges: readonly MatchRange[]): MatchResult {
  if (ranges.length === 0) {
    return unknown('no-ranges', NO_RANGES, isBranch(v));
  }
  if (v.scheme === 'opaque') {
    return evaluateOpaque(v, ranges);
  }
  let badRange: string | null = null;
  let hit: MatchRange | null = null;
  let hitIn = false;
  let hitFix: Version | null = null;
  for (const range of ranges) {
    let b: Bounds;
    try {
      b = readBounds(v.scheme, range);
    } catch (error) {
      badRange ??= error instanceof Error ? error.message : 'bad range';
      continue;
    }
    if (!isBranch(v)) {
      if (contains(b, v)) {
        return affected(v, range);
      }
      continue;
    }
    if (!intersectsBranch(b, v)) {
      continue;
    }
    // Prefer a range whose fix ships inside the branch, and among those the highest fix: a
    // floating tag runs the newest release of the branch, so that is the release to pull.
    const fix = b.fixed;
    const inside =
      fix !== null &&
      fix.depth === 0 &&
      compareVersions(fix, branchLow(v)) >= 0 &&
      compareVersions(fix, branchHigh(v)) < 0;
    if (hit === null || (inside && !hitIn)) {
      hit = range;
      hitIn = inside;
      hitFix = fix;
    } else if (inside && hitIn && hitFix !== null) {
      if (compareVersions(fix, hitFix) > 0) {
        hit = range;
        hitFix = fix;
      }
    }
  }
  if (hit !== null) {
    return affected(v, hit);
  }
  if (badRange !== null) {
    return unknown('unparseable-range', `${badRange}; check manually`);
  }
  return {
    outcome: 'not-affected',
    reason: 'outside-ranges',
    detail: isBranch(v)
      ? `no release of branch ${v.raw} is in the affected ranges`
      : `${v.raw} is outside the affected ranges`,
    range: null,
    fixedIn: '',
    branch: isBranch(v),
  };
}

/** Evaluates an advisory for a product at an already parsed version. */
export function checkVersion(v: Version, slug: string, advisory: MatchAdvisory): MatchResult {
  let listed = false;
  let unknownRanges = false;
  const ranges: MatchRange[] = [];
  for (const entry of advisory.affected) {
    if (entry.product !== slug) {
      continue;
    }
    listed = true;
    if (entry.ranges.length === 0) {
      unknownRanges = true;
    }
    ranges.push(...entry.ranges);
  }
  if (!listed) {
    return unknown(
      'product-not-listed',
      `${advisory.id} does not list ${slug}; check manually`,
      isBranch(v),
    );
  }
  const result = evaluateVersion(v, ranges);
  if (unknownRanges && result.outcome !== 'affected') {
    return unknown('no-ranges', NO_RANGES, isBranch(v));
  }
  return result;
}

/** Evaluates an advisory for a product at the installed branch or exact version. */
export function check(
  scheme: Scheme,
  installed: string,
  slug: string,
  advisory: MatchAdvisory,
): MatchResult {
  let v: Version;
  try {
    v = parseVersion(scheme, installed);
  } catch (error) {
    return unknown(
      'unparseable-version',
      `${error instanceof Error ? error.message : 'invalid version'}; check manually`,
    );
  }
  return checkVersion(v, slug, advisory);
}

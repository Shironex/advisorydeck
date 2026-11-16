import type { Advisory, CatalogEntry, VersionRange } from '@advisorydeck/contract';
import type { SourceIndex } from './source-index.ts';
import type { CveAffected, CveRecord, GhsaAdvisory, GhsaRecord } from './records.ts';
import {
  branchOf,
  cleanVersion,
  compareSemverLike,
  compactHyphenRange,
  dedupeRanges,
  isBounded,
  isRangeExpression,
  pairLowerBounds,
  parseRangeExpression,
  perBranchUpperBounds,
  singlePatchedVersion,
} from './versions.ts';

export type Severity = Advisory['severity'];
export type Reference = Advisory['references'][number];
export type SourceRef = Advisory['sources'][number];

/** One record's statement about one catalog product. */
export interface ProductClaim {
  slug: string;
  /** Index of the catalog source that produced the claim: lower is more trusted. */
  rank: number;
  /** Empty when the record names the product but its versions cannot be read. */
  ranges: VersionRange[];
}

/** Everything clustering needs from one upstream record. */
export interface RecordFacts {
  kind: 'cve' | 'ghsa';
  id: string;
  /** Other advisory ids this record says it is the same as. */
  links: string[];
  title: string | undefined;
  description: string | undefined;
  published: string | undefined;
  modified: string | undefined;
  severity: Severity | undefined;
  cwes: string[];
  references: Reference[];
  source: SourceRef;
  claims: ProductClaim[];
  warnings: string[];
}

/** Catalog lookups normalization needs: the source index plus where each source sits in its product. */
export interface Catalogue {
  entries: readonly CatalogEntry[];
  index: SourceIndex;
}

/** GHSA ecosystems that version a library, not the product itself. */
const LANGUAGE_ECOSYSTEMS = new Set([
  'actions',
  'composer',
  'erlang',
  'go',
  'maven',
  'npm',
  'nuget',
  'pip',
  'pub',
  'rubygems',
  'rust',
  'swift',
]);

const CVSS_KEYS = ['cvssV3_1', 'cvssV4_0', 'cvssV3_0', 'cvssV2_0'] as const;

export function levelFromScore(score: number): Severity['level'] {
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
}

function levelFromWord(word: string | null | undefined): Severity['level'] | undefined {
  switch (word?.toLowerCase()) {
    case 'critical':
      return 'critical';
    case 'high':
      return 'high';
    case 'medium':
    case 'moderate':
      return 'medium';
    case 'low':
      return 'low';
    default:
      return undefined;
  }
}

function vectorOrNull(vector: unknown): string | null {
  return typeof vector === 'string' && /^CVSS:[0-9.]+\//.test(vector) ? vector : null;
}

/** RFC 3339 UTC with milliseconds, or undefined. */
export function isoTime(raw: string | null | undefined): string | undefined {
  if (raw === null || raw === undefined || raw === '') return undefined;
  const withZone = /[zZ]|[+-]\d\d:?\d\d$/.test(raw) ? raw : `${raw}Z`;
  const time = new Date(withZone);
  return Number.isNaN(time.getTime()) ? undefined : time.toISOString();
}

function referenceType(url: string, tags: readonly string[] = []): Reference['type'] {
  if (tags.includes('vendor-advisory')) return 'advisory';
  if (tags.includes('patch')) return 'fix';
  if (tags.includes('release-notes')) return 'release-notes';
  if (tags.includes('issue-tracking') || tags.includes('exploit')) return 'report';
  if (/\/advisories\/GHSA-|\/security\//.test(url)) return 'advisory';
  if (/\/(commit|pull)\//.test(url)) return 'fix';
  if (/\/releases?\//.test(url)) return 'release-notes';
  return 'web';
}

/** Only well-formed https URLs are published. */
export function httpsUrl(raw: string): string | undefined {
  const url = raw.trim();
  if (!/^https:\/\/\S+$/.test(url)) return undefined;
  try {
    new URL(url);
    return url;
  } catch {
    return undefined;
  }
}

function rankOf(catalogue: Catalogue, slug: string, match: (source: unknown) => boolean): number {
  const entry = catalogue.entries.find((e) => e.product.slug === slug);
  const index = entry?.product.sources.findIndex(match) ?? -1;
  return index < 0 ? 99 : index;
}

function same(a: string | undefined, b: string | undefined): boolean {
  return (a ?? '').trim().toLowerCase() === (b ?? '').trim().toLowerCase();
}

/** A wildcard line written as a version (PHP: `8.2.*` lessThan 8.2.35) means its first release, 8.2.0. */
function lineStart(raw: string): string | undefined {
  const match = /^v?(\d+(?:\.\d+)*)\.\*$/.exec(raw);
  if (match?.[1] === undefined) return undefined;
  const parts = match[1].split('.');
  while (parts.length < 3) parts.push('0');
  return parts.join('.');
}

/**
 * Ranges of one CVE affected entry. Undefined when any affected version cannot be read: half a
 * range list would make a consumer say "not affected" for the part that was dropped.
 */
export function cveRanges(affected: CveAffected): VersionRange[] | undefined {
  const ranges: VersionRange[] = [];
  for (const v of affected.versions ?? []) {
    if (v.status !== 'affected') continue;
    const raw = (v.version ?? '').trim();
    if (isRangeExpression(raw)) {
      const parsed = parseRangeExpression(raw);
      if (parsed === undefined) return undefined;
      ranges.push(...parsed);
      continue;
    }
    const any = raw === '' || raw === '*' || /^(n\/a|unspecified|all)$/i.test(raw);
    const introduced = any ? '0' : cleanVersion(lineStart(raw) ?? raw);
    if (introduced === undefined) return undefined;
    const bound = v.lessThan ?? v.lessThanOrEqual;
    if (bound !== undefined) {
      if (bound.trim() === '*') {
        ranges.push({ introduced });
        continue;
      }
      const version = cleanVersion(bound);
      if (version === undefined) return undefined;
      ranges.push(
        v.lessThan !== undefined
          ? { introduced, fixed: version }
          : { introduced, last_affected: version },
      );
    } else {
      if (introduced === '0') return undefined;
      ranges.push({ introduced, last_affected: introduced });
    }
  }
  return dedupeRanges(ranges);
}

function cveSeverity(record: CveRecord): Severity | undefined {
  for (const key of CVSS_KEYS) {
    for (const metric of record.containers.cna.metrics ?? []) {
      const cvss = metric[key] as
        { baseScore?: unknown; baseSeverity?: unknown; vectorString?: unknown } | undefined;
      if (typeof cvss?.baseScore !== 'number') continue;
      return {
        level:
          levelFromWord(typeof cvss.baseSeverity === 'string' ? cvss.baseSeverity : undefined) ??
          levelFromScore(cvss.baseScore),
        score: cvss.baseScore,
        vector: vectorOrNull(cvss.vectorString),
        source: 'cna',
      };
    }
  }
  return undefined;
}

/** A GitHub advisory page: a repository advisory or the global database entry. */
const GHSA_PAGE =
  /^https:\/\/github\.com\/(?:[^/]+\/[^/]+\/security\/advisories|advisories)\/GHSA-([0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})(?:[/?#]|$)/i;

/**
 * The GHSA a CVE record was filed for, from its references (VulnCheck and GitHub link the
 * advisory page). Only a record that points at exactly one GHSA is linked: a record citing
 * several could join advisories that are not the same.
 */
function ghsaLinks(cveId: string, references: readonly Reference[], warnings: string[]): string[] {
  const ids = new Set<string>();
  for (const { url } of references) {
    const match = GHSA_PAGE.exec(url);
    if (match?.[1] !== undefined) ids.add(`GHSA-${match[1].toLowerCase()}`);
  }
  if (ids.size > 1) {
    warnings.push(
      `${cveId}: references several GitHub advisories (${[...ids].sort().join(', ')}), linked to none of them`,
    );
    return [];
  }
  return [...ids];
}

export function cveFacts(record: CveRecord, catalogue: Catalogue): RecordFacts {
  const { cveId, assignerShortName } = record.cveMetadata;
  const cna = record.containers.cna;
  const warnings: string[] = [];
  const claims: ProductClaim[] = [];
  const rules = catalogue.index.cna.get(assignerShortName) ?? [];
  for (const affected of cna.affected ?? []) {
    const rule = rules.find(
      (r) =>
        r.products.some((p) => same(p, affected.product)) &&
        (r.vendor === undefined || same(r.vendor, affected.vendor)),
    );
    if (rule === undefined) continue;
    const ranges = cveRanges(affected);
    if (ranges === undefined) {
      warnings.push(`${cveId}: unreadable versions for ${rule.slug}, published as unknown`);
    }
    claims.push({
      slug: rule.slug,
      rank: rankOf(
        catalogue,
        rule.slug,
        (s) =>
          (s as { type: string; assigner?: string }).type === 'cve-cna' &&
          (s as { assigner: string }).assigner === assignerShortName,
      ),
      ranges: ranges ?? [],
    });
  }
  const references: Reference[] = [];
  for (const ref of cna.references ?? []) {
    const url = httpsUrl(ref.url);
    if (url !== undefined) references.push({ url, type: referenceType(url, ref.tags) });
  }
  return {
    kind: 'cve',
    id: cveId,
    links: ghsaLinks(cveId, references, warnings),
    title: cna.title?.trim() || undefined,
    description: cna.descriptions?.[0]?.value.trim() || undefined,
    published: isoTime(record.cveMetadata.datePublished),
    modified: isoTime(record.cveMetadata.dateUpdated),
    severity: cveSeverity(record),
    cwes: (cna.problemTypes ?? []).flatMap((p) =>
      (p.descriptions ?? []).map((d) => d.cweId ?? '').filter((c) => /^CWE-[0-9]+$/.test(c)),
    ),
    references,
    source: {
      type: 'cve-cna',
      id: cveId,
      url: `https://www.cve.org/CVERecord?id=${cveId}`,
      license: 'CVE-TOU',
    },
    claims: perBranchClaims(mergeClaims(claims), cveId, warnings),
    warnings,
  };
}

function ghsaSeverity(advisory: GhsaAdvisory): Severity | undefined {
  for (const cvss of [advisory.cvss_severities?.cvss_v3, advisory.cvss_severities?.cvss_v4]) {
    if (typeof cvss?.score === 'number' && cvss.score > 0) {
      return {
        level: levelFromScore(cvss.score),
        score: cvss.score,
        vector: vectorOrNull(cvss.vector_string),
        source: 'ghsa',
      };
    }
  }
  const level = levelFromWord(advisory.severity);
  return level === undefined ? undefined : { level, score: null, vector: null, source: 'ghsa' };
}

export interface RangeReading {
  /** Undefined when the entry cannot be read: the product is then published with unknown versions. */
  ranges: VersionRange[] | undefined;
  /** Set when upstream data needed a judgement call, for data/quality.json. */
  note?: string;
}

/** The major of a Go module path with a major suffix (github.com/traefik/traefik/v2 gives 2). */
function goModuleMajor(name: string | null | undefined): number | undefined {
  const match = /\/v(\d+)$/.exec(name?.trim() ?? '');
  const major = match?.[1] === undefined ? undefined : Number(match[1]);
  return major !== undefined && major >= 2 ? major : undefined;
}

/**
 * Ranges of one GHSA vulnerability entry. The patched version fills a lone open range and, when
 * it is later than the written upper bound, replaces it (the stricter reading). A list of
 * patched versions next to "All" becomes one range per branch. A Go module with a major suffix
 * only holds that major, so an open lower bound starts at it (v2 starts at 2.0.0).
 */
export function ghsaRanges(vulnerability: GhsaAdvisory['vulnerabilities'][number]): RangeReading {
  const expression = (vulnerability.vulnerable_version_range ?? '').trim();
  const patchedRaw = (
    vulnerability.first_patched_version ??
    vulnerability.patched_versions ??
    ''
  ).trim();
  const reading = readGhsaRange(expression, patchedRaw);
  const major = goModuleMajor(vulnerability.package?.name);
  if (reading.ranges === undefined || major === undefined) return reading;
  return {
    ...reading,
    ranges: reading.ranges.map((r) =>
      r.introduced === '0' ? { ...r, introduced: `${major}.0.0` } : r,
    ),
  };
}

function readGhsaRange(expression: string, patchedRaw: string): RangeReading {
  const branchFixes = patchedBranchList(patchedRaw);
  const all = expression === '' || /^(all|\*|any)$/i.test(expression);
  if (all) {
    return branchFixes === undefined
      ? { ranges: undefined }
      : { ranges: perBranchRanges('0', branchFixes) };
  }
  const parsed = parseRangeExpression(expression);
  if (parsed === undefined) return { ranges: undefined };
  if (parsed.length > 1 && !parsed.some(isBounded)) {
    // Several lower bounds and no fix in them: either nothing is patched yet (keep the open
    // ranges) or a patched list says where each branch is fixed.
    if (!/[0-9]/.test(patchedRaw)) return { ranges: parsed };
    const paired = pairLowerBounds(parsed, branchFixes);
    return paired === undefined
      ? {
          ranges: undefined,
          note: `lower bounds "${expression}" do not pair with the patched versions "${patchedRaw}": versions unknown`,
        }
      : { ranges: paired };
  }
  const only = parsed.length === 1 ? parsed[0] : undefined;
  if (only === undefined) return { ranges: parsed };
  const open = only.fixed === undefined && only.last_affected === undefined;
  if (open && branchFixes !== undefined) {
    return { ranges: perBranchRanges(only.introduced, branchFixes) };
  }
  const patched = singlePatchedVersion(patchedRaw);
  if (patched === undefined) return { ranges: parsed };
  if (open) return { ranges: [{ introduced: only.introduced, fixed: patched }] };
  // Upstream often writes the range loosely next to an exact patched version: a bare
  // "v4.0.0-beta.428" or "< v4.0.0-beta.436" patched in the next beta, "<= 4.0.0-beta.473"
  // patched in 4.0.0-beta.474. When the patched version is later than the written upper bound,
  // the range ends at the patched version: a version between the two is reported affected rather
  // than silently not affected. When the two cannot be ordered, or a bare version is later than
  // its patch, the versions are published as unknown.
  const bare =
    /^v?[0-9][^\s<>=,]*$/.test(expression) && compactHyphenRange(expression) === undefined;
  const upper = only.fixed ?? only.last_affected ?? '';
  const order = compareSemverLike(patched, upper);
  if (bare) {
    if (order !== undefined && order > 0) {
      return {
        ranges: [{ introduced: '0', fixed: patched }],
        note: `affected "${expression}" is a single version while ${patched} is the patch: read as every version before ${patched}`,
      };
    }
    return {
      ranges: undefined,
      note: `affected "${expression}" and patched "${patchedRaw}" contradict each other: versions unknown`,
    };
  }
  if (order === undefined) {
    return only.fixed === undefined || only.fixed === patched
      ? { ranges: parsed }
      : {
          ranges: undefined,
          note: `range "${expression}" and patched "${patchedRaw}" cannot be ordered: versions unknown`,
        };
  }
  if (order > 0) {
    // "<= 3.7.17" patched in 3.7.18 is the normal shape; anything else leaves a gap.
    const normal = only.fixed === undefined && isNextPatch(upper, patched);
    return {
      ranges: [{ introduced: only.introduced, fixed: patched }],
      ...(normal
        ? {}
        : {
            note: `range "${expression}" ends before the patched version ${patched}: kept the stricter reading, affected up to ${patched}`,
          }),
    };
  }
  if (order < 0) {
    return {
      ranges: parsed,
      note: `range "${expression}" ends after the patched version ${patched}: kept the range, the stricter reading`,
    };
  }
  return { ranges: parsed };
}

/** True when patched is the release right after last (4.0.0-beta.473 then 4.0.0-beta.474, 3.7.17 then 3.7.18). */
function isNextPatch(last: string, patched: string): boolean {
  const a = /^(.*?)(\d+)$/.exec(last);
  const b = /^(.*?)(\d+)$/.exec(patched);
  return a !== null && b !== null && a[1] === b[1] && Number(b[2]) === Number(a[2]) + 1;
}

/** A comma-separated list of two or more exact patched versions, one per branch, sorted ascending. */
function patchedBranchList(raw: string): string[] | undefined {
  if (!raw.includes(',')) return undefined;
  const versions = raw.split(',').map((part) => cleanVersion(part));
  if (versions.some((v) => v === undefined || branchOf(v) === undefined)) return undefined;
  return (versions as string[]).sort((a, b) => compareSemverLike(a, b) ?? 0);
}

/**
 * One range per patched branch: the first starts at the given lower bound, each later one at the
 * start of its line (x.0.0 on a new major, so an unpatched x.0 line is still covered, else x.y.0).
 */
function perBranchRanges(first: string, fixes: readonly string[]): VersionRange[] {
  return fixes.map((fixed, i) => {
    const branch = branchOf(fixed);
    const previous = i === 0 ? undefined : branchOf(fixes[i - 1] ?? '');
    if (i === 0 || branch === undefined || previous === undefined)
      return { introduced: first, fixed };
    const introduced =
      branch.major === previous.major ? `${branch.major}.${branch.minor}.0` : `${branch.major}.0.0`;
    return { introduced, fixed };
  });
}

function packageKey(vulnerability: GhsaAdvisory['vulnerabilities'][number]): string | undefined {
  const ecosystem = vulnerability.package?.ecosystem?.trim().toLowerCase() ?? '';
  const name = vulnerability.package?.name?.trim() ?? '';
  return LANGUAGE_ECOSYSTEMS.has(ecosystem) ? `${ecosystem}:${name}` : undefined;
}

/** Collects ranges per product from the vulnerability entries a selector assigns to it. */
function claimsFrom(
  advisory: GhsaAdvisory,
  productFor: (vulnerability: GhsaAdvisory['vulnerabilities'][number]) => string | undefined,
  rank: (slug: string) => number,
  warnings: string[],
): ProductClaim[] {
  const bySlug = new Map<string, VersionRange[] | undefined>();
  for (const vulnerability of advisory.vulnerabilities) {
    const slug = productFor(vulnerability);
    if (slug === undefined) continue;
    const before = bySlug.get(slug);
    if (bySlug.has(slug) && before === undefined) continue;
    const name = vulnerability.package?.name ?? '';
    if (/\s{2,}|[<>\n\t]/.test(name.trim())) {
      warnings.push(
        `${advisory.ghsa_id}: malformed package name "${name.trim().replace(/\s+/g, ' ')}", entry read as ${slug}`,
      );
    }
    const { ranges, note } = ghsaRanges(vulnerability);
    if (note !== undefined) warnings.push(`${advisory.ghsa_id}: ${note}`);
    if (ranges === undefined) {
      warnings.push(
        `${advisory.ghsa_id}: unreadable or contradictory range "${vulnerability.vulnerable_version_range ?? ''}" (patched "${vulnerability.first_patched_version ?? vulnerability.patched_versions ?? ''}") for ${slug}, published as unknown`,
      );
      bySlug.set(slug, undefined);
    } else {
      bySlug.set(slug, [...(before ?? []), ...ranges]);
    }
  }
  return [...bySlug].map(([slug, ranges]) => ({
    slug,
    rank: rank(slug),
    ranges: dedupeRanges(ranges ?? []),
  }));
}

export function ghsaFacts(record: GhsaRecord, catalogue: Catalogue): RecordFacts {
  const { index } = catalogue;
  const warnings: string[] = [];
  const claims: ProductClaim[] = [];
  const repoSlug = record.repository === null ? undefined : index.ghsaRepos.get(record.repository);
  const named =
    record.repository === null ? undefined : index.ghsaRepoPackages.get(record.repository);
  if (record.repo !== null && repoSlug !== undefined && named !== undefined) {
    // The catalog names the entries that version this product; an advisory naming none of them
    // is about something else the repository ships (an app, a plugin, an installer).
    claims.push(
      ...claimsFrom(
        record.repo,
        (v) => (named.has((v.package?.name ?? '').trim().toLowerCase()) ? repoSlug : undefined),
        (slug) =>
          rankOf(
            catalogue,
            slug,
            (s) =>
              (s as { type: string }).type === 'ghsa-repo' &&
              (s as { repo: string }).repo === record.repository,
          ),
        warnings,
      ),
    );
  } else if (record.repo !== null && repoSlug !== undefined) {
    // A repository advisory belongs to the repository's product. When some entries name the
    // product itself (no language ecosystem, for example "Docker Engine" or "redis-server") or a
    // package the catalog gives this product, only those count: the others version a library in
    // another version line (Go module versions of moby). When no entry does, all entries count
    // (Coolify files some advisories under npm:coolify).
    const own = (v: GhsaAdvisory['vulnerabilities'][number]) => {
      const key = packageKey(v);
      return key === undefined || index.ghsaPackages.get(key) === repoSlug;
    };
    const useAll = !record.repo.vulnerabilities.some(own);
    const claimed = claimsFrom(
      record.repo,
      (v) => {
        if (useAll) {
          const key = packageKey(v);
          const owner = key === undefined ? undefined : index.ghsaPackages.get(key);
          return owner === undefined || owner === repoSlug ? repoSlug : undefined;
        }
        return own(v) ? repoSlug : undefined;
      },
      (slug) =>
        rankOf(
          catalogue,
          slug,
          (s) =>
            (s as { type: string }).type === 'ghsa-repo' &&
            (s as { repo: string }).repo === record.repository,
        ),
      warnings,
    );
    claims.push(
      ...(claimed.length > 0
        ? claimed
        : [
            {
              slug: repoSlug,
              rank: rankOf(
                catalogue,
                repoSlug,
                (s) => (s as { type: string }).type === 'ghsa-repo',
              ),
              ranges: [],
            },
          ]),
    );
  }
  if (record.global !== null) {
    claims.push(
      ...claimsFrom(
        record.global,
        (v) => {
          const key = packageKey(v);
          return key === undefined ? undefined : index.ghsaPackages.get(key);
        },
        (slug) =>
          rankOf(catalogue, slug, (s) => {
            const source = s as { type: string; ecosystem?: string; package?: string };
            return (
              source.type === 'ghsa-package' &&
              record.global?.vulnerabilities.some(
                (v) => packageKey(v) === `${source.ecosystem ?? ''}:${source.package ?? ''}`,
              ) === true
            );
          }),
        warnings,
      ),
    );
  }
  const primary = record.repo ?? record.global;
  if (primary === null) throw new Error(`${record.id}: no advisory body`);
  const links = new Set<string>();
  for (const advisory of [record.repo, record.global]) {
    if (advisory === null) continue;
    if (advisory.cve_id !== null) links.add(advisory.cve_id);
    for (const identifier of advisory.identifiers) {
      if (
        (identifier.type === 'CVE' || identifier.type === 'GHSA') &&
        identifier.value !== record.id
      ) {
        links.add(identifier.value);
      }
    }
  }
  const references: Reference[] = [];
  const advisoryUrl =
    record.repo !== null ? record.repo.html_url : `https://github.com/advisories/${record.id}`;
  references.push({ url: advisoryUrl, type: 'advisory' });
  for (const raw of [...(record.repo?.references ?? []), ...(record.global?.references ?? [])]) {
    const url = httpsUrl(raw);
    if (url !== undefined) references.push({ url, type: referenceType(url) });
  }
  const published = [record.repo?.published_at, record.global?.published_at]
    .map(isoTime)
    .filter((t): t is string => t !== undefined)
    .sort()[0];
  const modified = [record.repo?.updated_at, record.global?.updated_at]
    .map(isoTime)
    .filter((t): t is string => t !== undefined)
    .sort()
    .at(-1);
  return {
    kind: 'ghsa',
    id: record.id,
    links: [...links].sort(),
    title: primary.summary.trim() || undefined,
    description: primary.description?.trim() || undefined,
    published,
    modified,
    severity:
      (record.repo === null ? undefined : ghsaSeverity(record.repo)) ??
      (record.global === null ? undefined : ghsaSeverity(record.global)),
    cwes: [...(record.repo?.cwe_ids ?? []), ...(record.global?.cwe_ids ?? [])],
    references,
    source: { type: 'ghsa', id: record.id, url: advisoryUrl, license: 'CC-BY-4.0' },
    claims: perBranchClaims(mergeClaims(claims), record.id, warnings),
    warnings,
  };
}

/** Keeps the best claim per product and source rank (several entries can name one product). */
function mergeClaims(claims: readonly ProductClaim[]): ProductClaim[] {
  const out = new Map<string, ProductClaim>();
  for (const claim of claims) {
    const key = `${claim.slug}|${claim.rank}`;
    const before = out.get(key);
    out.set(
      key,
      before === undefined
        ? claim
        : {
            ...claim,
            // An empty list means unknown; unknown plus known is still unknown.
            ranges:
              before.ranges.length === 0 || claim.ranges.length === 0
                ? []
                : dedupeRanges([...before.ranges, ...claim.ranges]),
          },
    );
  }
  return [...out.values()];
}

/**
 * Reads upper bounds that each start at 0, one per branch, as one range per branch
 * (perBranchUpperBounds). The entries of one record are joined before this, so it applies both to
 * one entry listing several bounds and to several entries listing one each.
 */
function perBranchClaims(claims: ProductClaim[], id: string, warnings: string[]): ProductClaim[] {
  return claims.map((claim) => {
    const ranges = perBranchUpperBounds(claim.ranges);
    if (ranges === undefined) return claim;
    const bounds = ranges.map((r) => r.fixed ?? r.last_affected ?? '').join(', ');
    warnings.push(
      `${id}: upper bounds ${bounds} each from the first version read as one range per branch for ${claim.slug}, each from the line after the previous bound`,
    );
    return { ...claim, ranges };
  });
}

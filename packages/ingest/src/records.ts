/**
 * Upstream records as ingest keeps them in data/sources/: the fields normalization reads, nothing
 * else. Reporter names, credits and vendor extensions are dropped on the way in.
 */

export interface CveVersion {
  version?: string;
  status?: string;
  lessThan?: string;
  lessThanOrEqual?: string;
  versionType?: string;
}

export interface CveAffected {
  vendor?: string;
  product?: string;
  defaultStatus?: string;
  versions?: CveVersion[];
}

export interface CveRecord {
  cveMetadata: {
    cveId: string;
    assignerShortName: string;
    state: string;
    datePublished?: string;
    dateUpdated?: string;
  };
  containers: {
    cna: {
      title?: string;
      descriptions?: { lang: string; value: string }[];
      affected?: CveAffected[];
      problemTypes?: { descriptions?: { cweId?: string }[] }[];
      references?: { url: string; tags?: string[] }[];
      metrics?: Record<string, unknown>[];
    };
  };
}

export interface GhsaVulnerability {
  package: { ecosystem: string | null; name: string | null } | null;
  vulnerable_version_range: string | null;
  patched_versions?: string | null;
  first_patched_version?: string | null;
}

export interface GhsaCvss {
  vector_string: string | null;
  score: number | null;
}

export interface GhsaAdvisory {
  ghsa_id: string;
  cve_id: string | null;
  html_url: string;
  summary: string;
  description: string | null;
  severity: string | null;
  published_at: string | null;
  updated_at: string;
  withdrawn_at: string | null;
  cvss_severities: { cvss_v3?: GhsaCvss | null; cvss_v4?: GhsaCvss | null } | null;
  cwe_ids: string[];
  identifiers: { type: string; value: string }[];
  references: string[];
  vulnerabilities: GhsaVulnerability[];
}

/** One GHSA id; the repository copy and the global database copy can both exist. */
export interface GhsaRecord {
  id: string;
  /** owner/name of the repository the repo copy came from. */
  repository: string | null;
  repo: GhsaAdvisory | null;
  global: GhsaAdvisory | null;
}

export interface BranchRecord {
  name: string;
  eol: boolean;
  eol_date: string | null;
  latest: string | null;
}

function str(value: unknown): string | null {
  return typeof value === 'string' ? value : null;
}

/**
 * Text kept from upstream records gets plain hyphens for en and em dashes: the repository keeps
 * those characters out of every file, and the meaning of advisory text does not change.
 */
export function plainDashes(text: string): string {
  return text.replace(/[\u2013\u2014]/g, '-');
}

/** Keeps the fields of a CVE JSON 5 record that ingest reads. */
export function trimCve(raw: unknown): CveRecord | undefined {
  const record = raw as Partial<CveRecord> | null;
  const meta = record?.cveMetadata;
  const cna = record?.containers?.cna;
  if (meta === undefined || typeof meta.cveId !== 'string') return undefined;
  const out: CveRecord = {
    cveMetadata: {
      cveId: meta.cveId,
      assignerShortName: meta.assignerShortName,
      state: meta.state,
      ...(meta.datePublished === undefined ? {} : { datePublished: meta.datePublished }),
      ...(meta.dateUpdated === undefined ? {} : { dateUpdated: meta.dateUpdated }),
    },
    containers: { cna: {} },
  };
  if (cna === undefined) return out;
  const target = out.containers.cna;
  if (cna.title !== undefined) target.title = plainDashes(cna.title);
  const english = cna.descriptions?.filter((d) => d.lang.toLowerCase().startsWith('en'));
  if (english !== undefined && english.length > 0) {
    target.descriptions = english.map(({ lang, value }) => ({ lang, value: plainDashes(value) }));
  }
  if (cna.affected !== undefined) {
    target.affected = cna.affected.map((a) => ({
      ...(a.vendor === undefined ? {} : { vendor: a.vendor }),
      ...(a.product === undefined ? {} : { product: a.product }),
      ...(a.defaultStatus === undefined ? {} : { defaultStatus: a.defaultStatus }),
      ...(a.versions === undefined ? {} : { versions: a.versions }),
    }));
  }
  if (cna.problemTypes !== undefined) {
    target.problemTypes = cna.problemTypes.map((p) => ({
      descriptions: (p.descriptions ?? [])
        .filter((d) => typeof d.cweId === 'string')
        .map((d) => ({ cweId: d.cweId ?? '' })),
    }));
  }
  if (cna.references !== undefined) {
    target.references = cna.references.map((r) => ({
      url: r.url,
      ...(r.tags === undefined ? {} : { tags: r.tags }),
    }));
  }
  if (cna.metrics !== undefined) {
    target.metrics = cna.metrics.map((metric) => {
      const kept: Record<string, unknown> = {};
      for (const key of ['cvssV4_0', 'cvssV3_1', 'cvssV3_0', 'cvssV2_0']) {
        if (metric[key] !== undefined) kept[key] = metric[key];
      }
      return kept;
    });
  }
  return out;
}

/** Keeps the fields of a GHSA REST advisory (repository or global endpoint) that ingest reads. */
export function trimGhsa(raw: Record<string, unknown>): GhsaAdvisory {
  const cwes = Array.isArray(raw['cwe_ids'])
    ? (raw['cwe_ids'] as string[])
    : Array.isArray(raw['cwes'])
      ? (raw['cwes'] as { cwe_id: string }[]).map((c) => c.cwe_id)
      : [];
  const cvss = raw['cvss_severities'] as GhsaAdvisory['cvss_severities'] | undefined;
  const vulnerabilities = (raw['vulnerabilities'] as Record<string, unknown>[] | null) ?? [];
  const description = str(raw['description']);
  return {
    ghsa_id: String(raw['ghsa_id']),
    cve_id: str(raw['cve_id']),
    html_url: String(raw['html_url']),
    summary: plainDashes(str(raw['summary']) ?? ''),
    description: description === null ? null : plainDashes(description),
    severity: str(raw['severity']),
    published_at: str(raw['published_at']),
    updated_at: String(raw['updated_at']),
    withdrawn_at: str(raw['withdrawn_at']),
    cvss_severities: cvss ?? null,
    cwe_ids: [...cwes].sort(),
    identifiers: ((raw['identifiers'] as GhsaAdvisory['identifiers'] | null) ?? []).map(
      ({ type, value }) => ({ type, value }),
    ),
    references: Array.isArray(raw['references']) ? (raw['references'] as string[]) : [],
    vulnerabilities: vulnerabilities.map((v) => {
      const pkg = v['package'] as { ecosystem?: string | null; name?: string | null } | null;
      const out: GhsaVulnerability = {
        package: pkg === null ? null : { ecosystem: pkg.ecosystem ?? null, name: pkg.name ?? null },
        vulnerable_version_range: str(v['vulnerable_version_range']),
      };
      if ('patched_versions' in v) out.patched_versions = str(v['patched_versions']);
      if ('first_patched_version' in v) {
        const first = v['first_patched_version'];
        out.first_patched_version =
          typeof first === 'string'
            ? first
            : str((first as { identifier?: unknown } | null)?.identifier);
      }
      return out;
    }),
  };
}

/* Generated from schemas/v1 by packages/contract/scripts/gen-types.ts. Do not edit; run pnpm gen:types. */

export type Source =
  | CveCnaSource
  | GhsaRepoSource
  | GhsaPackageSource
  | OsvSource
  | VendorPageSource
  | VendorFeedSource;
/**
 * A reviewed note as it appears inside a published advisory. Only reviewed notes are ever published.
 */
export type FeedNote = {
  status: 'reviewed';
  audience: 'generic-selfhosters' | 'coolify-selfhosters';
  /**
   * Whether a default self-hosted setup is exposed. Always shown together with the assumptions.
   */
  exposure: 'default-exposed' | 'conditional' | 'not-default' | 'unknown';
  assumptions: Assumptions;
  actions: Actions;
  authorship: 'human' | 'model-drafted-human-reviewed';
  /**
   * A GitHub user name, without the @.
   */
  reviewed_by: string;
  reviewed_at: string;
  /**
   * The note text as Markdown.
   */
  body: string;
};
/**
 * The setup the exposure judgement assumes. Required (at least one) when exposure is conditional or not-default.
 */
export type Assumptions = string[];
export type Actions = NoteAction[];
/**
 * Front matter of a curated note: notes/<advisory-id>.md. The Markdown body below the front matter is the note text.
 */
export type CuratedNote = {
  /**
   * An advisory identifier such as CVE-2026-120154, GHSA-xxxx-xxxx-xxxx or USN-1234-1.
   */
  advisory: string;
  /**
   * @minItems 1
   *
   * Items: Stable public key of a product: lowercase letters, digits and single hyphens.
   */
  products: [string, ...string[]];
  audience: 'generic-selfhosters' | 'coolify-selfhosters';
  /**
   * Whether a default self-hosted setup is exposed. Always shown together with the assumptions.
   */
  exposure: 'default-exposed' | 'conditional' | 'not-default' | 'unknown';
  assumptions: Assumptions;
  actions: Actions;
  /**
   * draft: unreviewed, shown greyed out, never sent by the image. reviewed: checked by a reviewer, shown with reviewer and date, included in the feed. disputed: reported wrong, exposure hidden until resolved. superseded: replaced by newer information.
   */
  status: 'draft' | 'reviewed' | 'disputed' | 'superseded';
  authorship: 'human' | 'model-drafted-human-reviewed' | 'model-drafted';
  /**
   * A GitHub user name, without the @.
   */
  written_by?: string;
  /**
   * A GitHub user name, without the @.
   */
  reviewed_by?: string;
  reviewed_at?: string;
};

export interface Schemas {
  product?: Product;
  advisory?: Advisory;
  productFeed?: ProductFeed;
  manifest?: Manifest;
  imageConfig?: ImageConfig;
  curatedNote?: CuratedNote;
  correction?: Correction;
}
/**
 * One catalog entry: catalog/<category>/<slug>.yml. Says what the product is, how its versions compare and where its advisories come from.
 */
export interface Product {
  /**
   * Must equal the file name without .yml.
   */
  slug: string;
  name: string;
  /**
   * Must equal the folder the file sits in.
   */
  category:
    | 'databases'
    | 'proxies'
    | 'os'
    | 'paas'
    | 'containers'
    | 'runtimes'
    | 'auth'
    | 'monitoring'
    | 'storage'
    | 'devtools'
    | 'apps';
  homepage: string;
  description?: string;
  /**
   * How versions of a product compare. semver: semantic versions, prereleases included. semver4: semver with an optional fourth numeric part for vendor backports (Nextcloud Enterprise 31.0.14.7); a missing fourth part is 0, so 31.0.14 < 31.0.14.7 < 31.0.15. pg: PostgreSQL style major.minor (the major is the branch). calver: dotted calendar versions. dpkg: Debian package versions. kernel: Linux kernel versions. opaque: equality only.
   */
  version_scheme: 'semver' | 'semver4' | 'pg' | 'calver' | 'dpkg' | 'kernel' | 'opaque';
  branches: Branches;
  /**
   * Official container images and the grammar of their tags, used by the generator and optional discovery. Empty when the product is not usually run from an image.
   */
  images: Image[];
  /**
   * Where advisories for this product are found, ordered by trust (first is most trusted).
   *
   * @minItems 1
   */
  sources: [Source, ...Source[]];
  match: {
    /**
     * vendor-ranges: per-branch affected and fixed versions from the vendor or its CNA. package-ranges: ranges of a language package (OSV, GHSA). distro-notice: match on the distro release, not a version. release-only: no usable advisory data, new releases only.
     */
    strategy: 'vendor-ranges' | 'package-ranges' | 'distro-notice' | 'release-only';
  };
  upstream?: Upstream;
  /**
   * True when reviewed self-hoster notes are written for this product.
   */
  curated: boolean;
  /**
   * Items: Stable public key of a product: lowercase letters, digits and single hyphens.
   */
  tags?: string[];
  /**
   * Known quirks of this product's advisory data, for whoever maintains ingest.
   */
  data_notes?: string[];
}
/**
 * Where supported release branches and EOL dates come from.
 */
export interface Branches {
  source: 'endoflife' | 'none';
  /**
   * Product id on endoflife.date.
   */
  endoflife_slug?: string;
}
export interface Image {
  /**
   * Fully qualified repository, registry included, no tag.
   */
  ref: string;
  /**
   * Regular expression a version tag matches, with a named group version. Must work in both ECMAScript and Go RE2 (no lookarounds).
   */
  tag_pattern: string;
  note?: string;
}
/**
 * cvelistV5 records whose assigner and affected product match.
 */
export interface CveCnaSource {
  type: 'cve-cna';
  /**
   * cveMetadata.assignerShortName in the CVE record.
   */
  assigner: string;
  /**
   * containers.cna.affected[].product values that belong to this product. ["*"] takes every product of the vendor, for a CNA that names each package separately (Go: net/http, crypto/x509); it needs vendor.
   *
   * @minItems 1
   */
  products: [string, ...string[]];
  /**
   * containers.cna.affected[].vendor, when the assigner publishes for several vendors.
   */
  vendor?: string;
  note?: string;
}
/**
 * Security advisories published on a GitHub repository.
 */
export interface GhsaRepoSource {
  type: 'ghsa-repo';
  repo: string;
  /**
   * Package names of the advisory entries that version this product (vulnerabilities[].package.name, compared without case and surrounding spaces), for repositories whose advisories also list apps, plugins or installers. When set, only these entries count, and an advisory naming none of them is not about this product. An empty string matches an entry without a name.
   *
   * @minItems 1
   */
  packages?: [string, ...string[]];
  note?: string;
}
/**
 * GitHub Advisory Database entries for one package, as GHSA names its ecosystem and package.
 */
export interface GhsaPackageSource {
  type: 'ghsa-package';
  ecosystem: string;
  package: string;
  note?: string;
}
/**
 * OSV records for one package in one OSV ecosystem.
 */
export interface OsvSource {
  type: 'osv';
  ecosystem: string;
  package: string;
  note?: string;
}
/**
 * A human-readable vendor page: cross-check and a trigger to write a note, never parsed as the primary record.
 */
export interface VendorPageSource {
  type: 'vendor-page';
  url: string;
  note?: string;
}
/**
 * A vendor RSS or Atom feed of security announcements.
 */
export interface VendorFeedSource {
  type: 'vendor-feed';
  url: string;
  format: 'rss' | 'atom';
  note?: string;
}
/**
 * Set only when the upstream project no longer ships fixes (archived on its forge, retired by its vendor). Consumers show it next to every advisory and summary for the product, so a user knows to plan a move instead of waiting for a fix.
 */
export interface Upstream {
  /**
   * archived: the upstream repository or project is archived or retired and no further releases are expected.
   */
  status: 'archived';
  /**
   * When upstream archived or retired the project.
   */
  since?: string;
  /**
   * One or two plain sentences for the user: what happened and where to look (a maintained fork, the vendor's notice).
   */
  note?: string;
}
/**
 * One normalized advisory (an alias cluster). Ingest writes it to data/advisories/<id>.json; the same object appears in every products/<slug>.json it affects.
 */
export interface Advisory {
  /**
   * Cluster id: the CVE id when one exists, else the GHSA id, else the vendor id.
   */
  id: string;
  /**
   * Every other id in the cluster (GHSA, USN, DSA, vendor ids). Never contains id itself.
   *
   * Items: An advisory identifier such as CVE-2026-120154, GHSA-xxxx-xxxx-xxxx or USN-1234-1.
   */
  aliases: string[];
  title: string;
  /**
   * Plain text from the source record. Consumers must escape it.
   */
  summary: string;
  /**
   * RFC 3339 date and time in UTC.
   */
  published_at: string;
  /**
   * RFC 3339 date and time in UTC.
   */
  modified_at: string;
  severity: {
    /**
     * Qualitative severity. unknown means no score was found; it is shown, never dropped.
     */
    level: 'unknown' | 'low' | 'medium' | 'high' | 'critical';
    /**
     * CVSS base score, or null when there is none.
     */
    score: number | null;
    vector: string | null;
    /**
     * Which record the score came from, in the fallback order cna, ghsa, nvd, vendor; none when level is unknown.
     */
    source: 'cna' | 'ghsa' | 'nvd' | 'vendor' | 'none';
  };
  /**
   * Listed in the CISA Known Exploited Vulnerabilities catalog. listed is only a real no when checked is true: without checked (or with checked false) the catalog was not read for this advisory, so consumers must say not checked, never not listed.
   */
  kev: {
    listed: boolean;
    added_at: string | null;
    /**
     * True when the advisory's CVE ids were looked up in the KEV catalog. Missing or false means not checked. Ingest always writes it.
     */
    checked?: boolean;
  };
  /**
   * FIRST EPSS exploit probability, or null when unknown.
   */
  epss: null | {
    score: number;
    percentile: number;
    date: string;
  };
  cwes?: string[];
  /**
   * @minItems 1
   */
  affected: [AffectedProduct, ...AffectedProduct[]];
  /**
   * Products whose ranges Advisorydeck corrected by hand because the upstream record is wrong (a typo that makes current releases read affected). The ranges in affected are already the corrected ones; show the reason and the evidence next to them. Absent when nothing was corrected.
   *
   * @minItems 1
   */
  corrections?: [AppliedCorrection, ...AppliedCorrection[]];
  references: {
    url: string;
    type: 'advisory' | 'fix' | 'release-notes' | 'report' | 'article' | 'web';
  }[];
  /**
   * The records this advisory was built from, for attribution.
   *
   * @minItems 1
   */
  sources: [
    {
      type: 'cve-cna' | 'ghsa' | 'osv' | 'nvd' | 'kev' | 'epss' | 'vendor-page' | 'vendor-feed';
      id: string;
      url: string;
      /**
       * License or terms the record is used under, for example CVE-TOU or CC-BY-4.0.
       */
      license: string;
    },
    ...{
      type: 'cve-cna' | 'ghsa' | 'osv' | 'nvd' | 'kev' | 'epss' | 'vendor-page' | 'vendor-feed';
      id: string;
      url: string;
      /**
       * License or terms the record is used under, for example CVE-TOU or CC-BY-4.0.
       */
      license: string;
    }[]
  ];
  /**
   * Opaque material revision. It changes only on a material change (severity level, ranges, KEV, EPSS threshold, reviewed note); consumers renotify when it changes.
   */
  revision: string;
  /**
   * The reviewed curated note, or null. Drafts and disputed notes are never published here.
   */
  note: null | FeedNote;
}
export interface AffectedProduct {
  /**
   * Stable public key of a product: lowercase letters, digits and single hyphens.
   */
  product: string;
  /**
   * Affected version ranges in the product's version scheme. An empty list means the affected versions are unknown: consumers must say check manually, never not affected.
   */
  ranges: VersionRange[];
}
/**
 * introduced is inclusive (0 means from the first version); fixed is exclusive; last_affected is inclusive. At most one of fixed and last_affected; neither means no fix yet.
 */
export interface VersionRange {
  /**
   * A version or branch string as the vendor writes it, without a leading v.
   */
  introduced: string;
  /**
   * A version or branch string as the vendor writes it, without a leading v.
   */
  fixed?: string;
  /**
   * A version or branch string as the vendor writes it, without a leading v.
   */
  last_affected?: string;
}
/**
 * A hand correction as it appears inside a published advisory: the ranges of product were corrected by Advisorydeck because the upstream record is wrong.
 */
export interface AppliedCorrection {
  /**
   * Stable public key of a product: lowercase letters, digits and single hyphens.
   */
  product: string;
  /**
   * An advisory identifier such as CVE-2026-120154, GHSA-xxxx-xxxx-xxxx or USN-1234-1.
   */
  advisory: string;
  reason: string;
  /**
   * @minItems 1
   */
  evidence: [string, ...string[]];
  corrected_at: string;
  /**
   * What the upstream record said, as ingest read it, for comparison. An empty list means upstream gave no readable range.
   */
  upstream_ranges: VersionRange[];
}
export interface NoteAction {
  kind: 'upgrade' | 'backup' | 'commands' | 'config' | 'restart' | 'read';
  text?: string;
  code?: string;
}
/**
 * Published at api/v1/products/<slug>.json: everything a consumer needs to match one product locally.
 */
export interface ProductFeed {
  schema: 'advisorydeck/v1/product-feed';
  /**
   * RFC 3339 date and time in UTC.
   */
  generated_at: string;
  product: {
    /**
     * Stable public key of a product: lowercase letters, digits and single hyphens.
     */
    slug: string;
    name: string;
    /**
     * Catalog category. databases (databases, caches, queues and search engines), proxies (web servers, reverse proxies and load balancers), os (operating systems and kernels), paas (self-hosted platforms), containers (container engines such as dockerd and containerd, runc, orchestration and container tooling), runtimes (language runtimes that app containers run on), auth (identity, single sign-on and secrets), monitoring (metrics, logs, dashboards and uptime checks), storage (files, photos, media, backups, object storage and image registries), devtools (git hosting, CI and remote development environments), apps (applications deployed from templates: CMS, chat, automation, AI front ends).
     */
    category:
      | 'databases'
      | 'proxies'
      | 'os'
      | 'paas'
      | 'containers'
      | 'runtimes'
      | 'auth'
      | 'monitoring'
      | 'storage'
      | 'devtools'
      | 'apps';
    homepage: string;
    /**
     * How versions of a product compare. semver: semantic versions, prereleases included. semver4: semver with an optional fourth numeric part for vendor backports (Nextcloud Enterprise 31.0.14.7); a missing fourth part is 0, so 31.0.14 < 31.0.14.7 < 31.0.15. pg: PostgreSQL style major.minor (the major is the branch). calver: dotted calendar versions. dpkg: Debian package versions. kernel: Linux kernel versions. opaque: equality only.
     */
    version_scheme: 'semver' | 'semver4' | 'pg' | 'calver' | 'dpkg' | 'kernel' | 'opaque';
    upstream?: Upstream;
    /**
     * Release branches known for the product (from endoflife.date), newest first. Empty when the catalog has no branch source.
     */
    branches: {
      /**
       * A version or branch string as the vendor writes it, without a leading v.
       */
      name: string;
      eol: boolean;
      eol_date: string | null;
      latest: string | null;
    }[];
  };
  /**
   * Advisories that list this product in affected, newest published first.
   */
  advisories: Advisory[];
}
/**
 * Published at api/v1/manifest.json. Small on purpose: a consumer fetches it with If-None-Match and downloads only the product files whose etag changed.
 */
export interface Manifest {
  schema: 'advisorydeck/v1/manifest';
  /**
   * RFC 3339 date and time in UTC.
   */
  generated_at: string;
  /**
   * One entry per published product; the file is products/<slug>.json next to this manifest.
   */
  products: {
    [k: string]: ManifestEntry | undefined;
  };
}
export interface ManifestEntry {
  /**
   * RFC 3339 date and time in UTC.
   */
  updated_at: string;
  /**
   * sha256 of the exact bytes of the file it describes.
   */
  etag: string;
  /**
   * Number of advisories in the product file.
   */
  advisories: number;
}
/**
 * The notifier image's config file (advisorydeck.yml), mounted read-only. Webhook URLs are secrets: the file names the environment variables that hold them and never contains them.
 */
export interface ImageConfig {
  version: 1;
  feed: {
    /**
     * Base URL of the published feed, ending in /api/v1/.
     */
    url: string;
    /**
     * How often to check the manifest, for example 30m. Minimum 5m. Default 30m.
     */
    poll_interval?: string;
  };
  /**
   * What you run. version is a branch (17) or an exact version (17.4). Each slug at most once.
   *
   * @minItems 1
   */
  products: [WatchedProduct, ...WatchedProduct[]];
  /**
   * Lowest severity to notify. Default high. Bypass rules (KEV, required curated action) ignore it.
   */
  min_severity?: 'low' | 'medium' | 'high' | 'critical';
  /**
   * instant: post each match when seen. digest: one daily message, bypass rules still post instantly. both: post each match and include it in the digest. Default digest.
   */
  mode?: 'instant' | 'digest' | 'both';
  digest?: {
    /**
     * Local time of the daily digest, HH:MM. Default 08:00.
     */
    time?: string;
    /**
     * IANA time zone name. Default UTC.
     */
    timezone?: string;
  };
  /**
   * @minItems 1
   */
  channels: [Channel, ...Channel[]];
  /**
   * Where the image keeps what it already sent. Default /data/state.json.
   */
  state_path?: string;
}
export interface WatchedProduct {
  /**
   * Stable public key of a product: lowercase letters, digits and single hyphens.
   */
  slug: string;
  /**
   * A version or branch string as the vendor writes it, without a leading v.
   */
  version: string;
}
export interface Channel {
  type: 'discord' | 'slack' | 'webhook';
  /**
   * Name of the environment variable that holds the webhook URL.
   */
  url_env: string;
  name?: string;
}
/**
 * A reviewed hand correction of one upstream advisory for one product: corrections/<product>/<advisory-id>.yml. Ingest replaces the ranges it read from upstream with these ranges and says so on the advisory.
 */
export interface Correction {
  /**
   * An advisory identifier such as CVE-2026-120154, GHSA-xxxx-xxxx-xxxx or USN-1234-1.
   */
  advisory: string;
  /**
   * Stable public key of a product: lowercase letters, digits and single hyphens.
   */
  product: string;
  /**
   * Why the upstream ranges are wrong, in one or two plain sentences written by a person. Shown on the site next to the advisory.
   */
  reason: string;
  /**
   * Where the corrected ranges come from: the vendor's release notes, the fix commit or the upstream issue reporting the typo.
   *
   * @minItems 1
   */
  evidence: [string, ...string[]];
  /**
   * When the correction was written.
   */
  corrected_at: string;
  /**
   * The ranges ingest read from upstream when the correction was written. When the upstream reading changes, ingest still applies the correction but warns that it needs a recheck.
   */
  upstream_ranges: VersionRange[];
  /**
   * The corrected affected ranges, in the product's version scheme, in the order they are published.
   *
   * @minItems 1
   */
  ranges: [VersionRange, ...VersionRange[]];
}

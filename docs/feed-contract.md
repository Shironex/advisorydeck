# Feed contract (v1)

The published feed is the only interface between the site and every installed image. It is versioned in the URL: everything below lives under `<base>/api/v1/`.

| File                   | Schema                                                 | Purpose                                                           |
| ---------------------- | ------------------------------------------------------ | ----------------------------------------------------------------- |
| `manifest.json`        | [manifest](../schemas/v1/manifest.schema.json)         | Small index: one entry per product with its etag                  |
| `products/<slug>.json` | [product-feed](../schemas/v1/product-feed.schema.json) | The product (scheme, branches) and every advisory that affects it |

Each advisory inside a product file follows [advisory](../schemas/v1/advisory.schema.json); a reviewed note inside an advisory follows `FeedNote` in [curated-note](../schemas/v1/curated-note.schema.json). Each document carries a `schema` marker (`advisorydeck/v1/manifest`, `advisorydeck/v1/product-feed`); a consumer refuses a marker it does not know.

Examples: [fixtures/api/v1/](../fixtures/api/v1/).

## How a consumer polls

1. `GET manifest.json` with `If-None-Match`. A `304` means nothing changed.
2. For each product the user watches, compare `products.<slug>.etag` with the etag it saw last time.
3. Download only the changed `products/<slug>.json`. Its sha256 must equal the etag; if not, the file was caught mid-deploy: retry on the next poll.
4. Match locally. Renotify an advisory only when its `revision` changes.

`etag` is `sha256:` plus the hex sha256 of the exact file bytes, so a consumer can verify it without trusting HTTP headers. `generated_at` lets a consumer warn when the feed is stale. Ingest only moves a product's `generated_at` (and its manifest `updated_at`) when that product file changes, and the manifest's `generated_at` when any entry changes, so a run with nothing new rewrites nothing; quiet weeks are normal, and a staleness warning should allow for them.

## Field semantics

- **`id`** is the cluster id: the CVE id when there is one, else the GHSA id, else the vendor id. `aliases` lists the other ids and never repeats `id`. When a CVE is filed later for an advisory published under its GHSA id, the id becomes the CVE id and the GHSA id moves to `aliases`; match on `id` and `aliases` together.
- **`affected[].ranges`**, in the product's `version_scheme`:
  - `introduced` is inclusive; `"0"` means from the first version.
  - `fixed` is exclusive; `last_affected` is inclusive; never both; neither means no fix yet.
  - A bound that names a branch covers the whole branch: `last_affected: "1.29"` is every 1.29 release. A lower bound can be the lowest prerelease of a release (`introduced: "8.8.0-0"`, every prerelease of 8.8.0 and up), as Go's own records write it.
  - One range per branch is normal (PostgreSQL: `17` to `17.12`, `16` to `16.16`, ...).
  - **An empty list means the affected versions are unknown.** Say "check manually"; never "not affected".
- **`corrections`** is present only when Advisorydeck corrected the ranges of a product by hand because the upstream record is wrong (for example a bound of `< 26.37.1` next to the patched version `26.7.1`). The ranges in `affected` are already the corrected ones. Each entry names the `product`, the `advisory` id the correction is filed under, the `reason`, the `evidence` links, `corrected_at` and `upstream_ranges` (what upstream said, as read). Show the reason next to the ranges, so a user who compares with the vendor page knows why they differ. Added in v1 (additive).
- **`severity.level`** is `unknown`, `low`, `medium`, `high` or `critical`. `unknown` is published, never dropped. `score` and `vector` are null when there is no CVSS data; `source` says which record the score came from (`cna`, `ghsa`, `nvd`, `vendor`, or `none`).
- **`kev`** is the CISA KEV status. `checked` says whether the catalog was read for this advisory: `listed: false` with `checked: false` (or no `checked`, as in feeds from before enrichment) means **not checked**, never "not in KEV". `listed: true` always has `checked: true`. Show three states: in KEV, not in KEV, not checked.
- **`epss`** is the FIRST EPSS score (probability of exploitation in the next 30 days), its percentile and the score date; null when EPSS has not scored the CVE. It is refreshed only on a meaningful move, so the date can be older than a day. The image treats a percentile of 0.95 or above as a signal.
- **`sources[].type`** can be `kev`, `epss` or `nvd` besides the advisory sources; their licenses are `CC0-1.0`, `FIRST-EPSS` and `NVD-TOU`.
- **`note`** is null unless a reviewed note exists. Drafts, disputed and superseded notes are never in the feed. The exposure label must be shown together with its assumptions.
- **`revision`** is opaque. It changes only on a material change (severity level, ranges, a KEV listing, EPSS crossing the 0.95 percentile, the reviewed note), not on description edits.
- **`product.upstream`** is present only when the catalog marks the upstream project as archived: `status` (`archived`; treat an unknown status as a warning too), `since` (date, optional) and `note` (optional, for example the maintained alternative). No further fixes are expected; show it next to the product.
- **`product.category`** gained `auth`, `monitoring`, `storage`, `devtools` and `apps` in this version (additive); treat an unknown category as uncategorized.
- **Text fields** (`title`, `summary`, note `body`) come from third parties or contributors. Escape them, truncate them for the target channel, and never let them trigger mentions.

## Versioning rules

- **Additive changes stay in v1**: a new optional field, a new file, a new enum value. Consumers must ignore unknown fields and treat an unknown enum value like `unknown` (or skip the item) instead of failing. The Go image decodes with `encoding/json`, which ignores unknown fields.
- **Breaking changes make v2**: renaming or removing a field, changing a type or meaning, making an optional field required. v2 gets its own `schemas/v2/`, its own `api/v2/` and new schema markers; v1 keeps being published until installed images have moved.
- The schemas in this repository are strict (`additionalProperties: false`) so producers cannot drift by accident. Any change to the published shape updates the schema, the fixtures and the generated types (`pnpm gen:types`) in the same pull request.

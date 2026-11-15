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

`etag` is `sha256:` plus the hex sha256 of the exact file bytes, so a consumer can verify it without trusting HTTP headers. `generated_at` lets a consumer warn when the feed is stale.

## Field semantics

- **`id`** is the cluster id: the CVE id when there is one, else the GHSA id, else the vendor id. `aliases` lists the other ids and never repeats `id`.
- **`affected[].ranges`**, in the product's `version_scheme`:
  - `introduced` is inclusive; `"0"` means from the first version.
  - `fixed` is exclusive; `last_affected` is inclusive; never both; neither means no fix yet.
  - One range per branch is normal (PostgreSQL: `17` to `17.12`, `16` to `16.16`, ...).
  - **An empty list means the affected versions are unknown.** Say "check manually"; never "not affected".
- **`severity.level`** is `unknown`, `low`, `medium`, `high` or `critical`. `unknown` is published, never dropped. `score` and `vector` are null when there is no CVSS data; `source` says which record the score came from (`cna`, `ghsa`, `nvd`, `vendor`, or `none`).
- **`kev.listed`** and **`epss`** are exploitation signals; `epss` is null when unknown.
- **`note`** is null unless a reviewed note exists. Drafts, disputed and superseded notes are never in the feed. The exposure label must be shown together with its assumptions.
- **`revision`** is opaque. It changes only on a material change (severity level, ranges, KEV, an EPSS threshold, the reviewed note), not on description edits.
- **Text fields** (`title`, `summary`, note `body`) come from third parties or contributors. Escape them, truncate them for the target channel, and never let them trigger mentions.

## Versioning rules

- **Additive changes stay in v1**: a new optional field, a new file, a new enum value. Consumers must ignore unknown fields and treat an unknown enum value like `unknown` (or skip the item) instead of failing. The Go image decodes with `encoding/json`, which ignores unknown fields.
- **Breaking changes make v2**: renaming or removing a field, changing a type or meaning, making an optional field required. v2 gets its own `schemas/v2/`, its own `api/v2/` and new schema markers; v1 keeps being published until installed images have moved.
- The schemas in this repository are strict (`additionalProperties: false`) so producers cannot drift by accident. Any change to the published shape updates the schema, the fixtures and the generated types (`pnpm gen:types`) in the same pull request.

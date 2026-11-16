# Architecture

Advisorydeck is a static pipeline. There is no server and no database: scheduled jobs turn public advisory data into committed JSON, a static site publishes it, and a small image on each user's server polls the published files and matches locally.

## Data flow

```
 catalog/<category>/<slug>.yml      upstream sources
 notes/<advisory-id>.md             (cvelistV5, GHSA, OSV, KEV, EPSS, vendor feeds)
            |                                |
            +---------------+----------------+
                            v
            packages/ingest  (scheduled GitHub Actions)
                            |
                            v
            data/advisories/<id>.json        committed, reviewable diffs
                            |
                            v
            apps/site build  (Astro, static)
                            |
                            v
            dist/                            HTML pages, Atom feeds
            dist/api/v1/manifest.json        the feed contract
            dist/api/v1/products/<slug>.json
                            |
                            |  HTTPS, If-None-Match
                            v
            image/  (Go, on the user's server)
            poll manifest -> fetch changed products -> match locally -> post webhooks
```

1. **Catalog** (`catalog/`): one YAML file per product, validated against `schemas/v1/product.schema.json`. It says how versions compare (`version_scheme`), where branches come from (`branches`), which images exist (`images`) and where advisories are found (`sources`, most trusted first).
2. **Ingest** (`packages/ingest`): reads upstream bulk data, keeps the records that belong to a catalog product, clusters aliases (CVE, GHSA, USN ...) into one advisory, extracts per-product ranges, enriches with KEV and EPSS, attaches reviewed notes, and writes `data/advisories/<id>.json` (`schemas/v1/advisory.schema.json`). "Matching" in ingest means deciding which product an upstream record belongs to; the lookup tables for that come from the catalog (`buildSourceIndex`).
3. **Notes** (`notes/`): curated Markdown files, CC-BY-4.0. Only `status: reviewed` notes are copied into advisories (`toFeedNote` in `packages/contract`).
4. **Site** (`apps/site`): builds HTML pages and writes the feed: `api/v1/manifest.json` and one `api/v1/products/<slug>.json` per product. The feed format is in [feed-contract.md](feed-contract.md).
5. **Image** (`image/`): a Go binary in a small container. It reads its config (`schemas/v1/image-config.schema.json`), polls the manifest, downloads only products whose etag changed, compares the user's versions against the ranges and posts to Discord, Slack or a generic webhook. It never needs the Docker socket, and it only downloads public files, so the feed host never learns what anyone runs.

## Where version matching lives

Comparing "I run 17.4" against "fixed in 17.12" happens in the image, in Go, because the image is the consumer that knows the user's versions. The matcher lives in `image/internal/match`: it parses every `version_scheme` (`semver`, `pg`, `calver`, `dpkg`, `kernel`, `opaque`), evaluates an advisory's per-branch ranges and resolves image tags with the catalog's `tag_pattern`. It is a pure library with no I/O.

Every answer is one of three outcomes, each with a reason code:

- **affected**: an exact version is inside a range, or (for a branch such as `17` or a floating tag such as `postgres:17`) some release of the branch is. A branch answer names the fix to pull, because a floating tag is only safe if it was pulled after the fix release.
- **not affected**: every range was read and none covers the version or any release of the branch. This is the only way to get it.
- **unknown**: the advisory has no ranges (an empty list, or a repo advisory that says All and TBD), the version or a range bound cannot be read, the scheme cannot order versions, or the tag names no version (`latest`, `alpine`, a codename). The image says "check manually". The zero value of the result type is unknown, so nothing reads as safe by default.

The matcher's test vectors are plain JSON in [`fixtures/match/`](../fixtures/match/) (real advisories, each with its source and the ranges as published, plus version and tag cases), so a TypeScript port can run the same cases.

## The seams

Every part talks to the others through files described by a schema in `schemas/v1/`, never through shared code. Each seam has a hand-made fixture so the parts can be built in parallel.

| Seam          | Producer                       | Consumers                          | Schema         | Fixture                         |
| ------------- | ------------------------------ | ---------------------------------- | -------------- | ------------------------------- |
| Catalog entry | humans (PRs)                   | ingest, site, image (tag patterns) | `product`      | `catalog/*` (real data)         |
| Curated note  | humans (PRs)                   | ingest, site                       | `curated-note` | `fixtures/notes/`               |
| Advisory      | ingest                         | site                               | `advisory`     | `fixtures/data/advisories/`     |
| Manifest      | site build                     | image                              | `manifest`     | `fixtures/api/v1/manifest.json` |
| Product feed  | site build                     | image                              | `product-feed` | `fixtures/api/v1/products/`     |
| Image config  | user (or the site's generator) | image                              | `image-config` | `fixtures/image/`               |

How the two languages stay on the same contract:

- **TypeScript**: `packages/contract` generates types from the schemas (`pnpm gen:types`, CI fails when they are stale), validates with Ajv, and `pnpm validate` checks the catalog, notes and every fixture, including cross-file rules (manifest etag equals the product file's sha256, feed notes equal their note files, products exist in the catalog).
- **Go**: `image/internal/feed` and `image/internal/config` hold hand-written types. Their tests decode the same fixtures and validate them against the same schema files with a Go JSON Schema validator, and `TestFixturesAgreeWithSchema` proves the Go config rules accept and reject exactly what the schema does, plus the rules a schema cannot express (`fixtures/image/invalid-semantic/`).

## Repository layout

| Path                            | Language             | Notes                                                        |
| ------------------------------- | -------------------- | ------------------------------------------------------------ |
| `catalog/<category>/<slug>.yml` | YAML                 | Slug equals the file name, category equals the folder        |
| `schemas/v1/*.schema.json`      | JSON Schema 2020-12  | `$id` under `raw.githubusercontent.com/.../schemas/v1/`      |
| `notes/<advisory-id>.md`        | Markdown             | Own license (CC-BY-4.0)                                      |
| `data/advisories/`              | JSON                 | Written by ingest; does not exist yet                        |
| `fixtures/`                     | JSON, YAML, Markdown | Hand-made, see [fixtures/README.md](../fixtures/README.md)   |
| `packages/contract`             | TypeScript           | Shared by ingest and site; consumed as source, no build step |
| `packages/ingest`               | TypeScript           |                                                              |
| `apps/site`                     | Astro                | Static output in `apps/site/dist`                            |
| `image/`                        | Go                   | Module `github.com/Shironex/advisorydeck/image`              |

The layout differs from the first design sketch in a few places, on purpose: schemas sit in `schemas/v1/` so a breaking v2 can live beside v1; notes live in `notes/` (not `curated/`) because that folder carries its own license; TypeScript code follows the pnpm workspace convention (`packages/`, `apps/`); and `packages/contract` exists so the site does not depend on ingest to get types and validators.

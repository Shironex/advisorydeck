# Fixtures

Hand-made example data in the exact shapes of [schemas/v1](../schemas/v1/). Every part of the project tests against these files, so ingest, the matcher, the site and the image can be built in parallel. They are test data: the note and its reviewer are examples, not reviewed guidance.

| Path                                   | Schema       | Used by                                       |
| -------------------------------------- | ------------ | --------------------------------------------- |
| `data/advisories/CVE-2026-120154.json` | advisory     | ingest (target shape), site                   |
| `api/v1/manifest.json`                 | manifest     | image, site (output shape)                    |
| `api/v1/products/postgresql.json`      | product-feed | image, matcher, site                          |
| `notes/CVE-2026-120154.md`             | curated-note | ingest, site                                  |
| `image/*.yml`                          | image-config | image, generator: valid configs               |
| `image/invalid/*.yml`                  | image-config | must fail the schema and the image            |
| `image/invalid-semantic/*.yml`         | image-config | pass the schema, fail the image's extra rules |

The advisory is built from the real CVE record for CVE-2026-120154 (PostgreSQL, published 2026-11-12), and the branch data from endoflife.date on the same week.

## Rules

`pnpm validate` enforces them:

- The advisory in `data/advisories/` and the copy inside `products/postgresql.json` are identical.
- The advisory's `note` equals what `toFeedNote` makes of `notes/CVE-2026-120154.md`.
- `manifest.json` lists every product file, with its advisory count and an `etag` equal to `sha256:` plus the sha256 of the file's exact bytes.

So after editing `products/postgresql.json`, run Prettier on it and then `pnpm validate`: a stale etag is reported together with the correct value to paste into `manifest.json`.

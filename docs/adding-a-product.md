# Adding a product

One product is one YAML file: `catalog/<category>/<slug>.yml`. The schema is [schemas/v1/product.schema.json](../schemas/v1/product.schema.json); the existing entries are good examples ([postgresql.yml](../catalog/databases/postgresql.yml), [traefik.yml](../catalog/proxies/traefik.yml)).

## Before you start

The catalog is small on purpose. A product belongs here when self-hosters commonly run it **and** its advisories are published somewhere machine-readable (a CNA writing CVE records, GitHub security advisories, OSV, a vendor feed). Without that, use `match.strategy: release-only` and say so in the request.

## Steps

1. **Pick the slug and category.** The slug is lowercase with hyphens and equals the file name. The category is one of `databases`, `proxies`, `os`, `paas`, `containers`, `runtimes` and equals the folder.
2. **Version scheme.** `semver` for most products (prereleases such as `4.0.0-beta.474` compare correctly), `pg` for PostgreSQL-style major.minor, `dpkg` and `kernel` for distro packages, `calver` for dotted dates, `opaque` when only equality makes sense.
3. **Branches.** If the product is on [endoflife.date](https://endoflife.date), set `source: endoflife` and its `endoflife_slug` (check `https://endoflife.date/api/v1/products/<slug>`). Otherwise `source: none`.
4. **Images.** List the official images with a fully qualified `ref` (`docker.io/library/postgres`, `ghcr.io/owner/name`) and a `tag_pattern` with a named group `version`. Patterns must work in JavaScript and in Go, so no lookarounds. Add a test row for real tags in `packages/contract/test/catalog.test.ts`.
5. **Sources, most trusted first.** Verify each one against the real data:
   - `cve-cna`: open a recent CVE record in [cvelistV5](https://github.com/CVEProject/cvelistV5) and copy `cveMetadata.assignerShortName` and `containers.cna.affected[].product` (and `vendor` if the assigner publishes for many vendors, as `GitHub_M` does).
   - `ghsa-repo`: the repository's security advisories (`gh api repos/<owner>/<repo>/security-advisories`).
   - `ghsa-package` and `osv`: the ecosystem and package name exactly as the advisories write them.
   - `vendor-feed` and `vendor-page`: an RSS or Atom feed, or the vendor's security page.
6. **Match strategy.** `vendor-ranges`, `package-ranges`, `distro-notice` or `release-only` (see the schema descriptions).
7. **Data notes.** Record every quirk you saw in the real records (a leading `v`, `TBD` fixed versions, ranges inside a version string) under `data_notes`. Ingest depends on them.
8. **Check.** `pnpm validate` and `pnpm test`, and `go test ./...` in `image/` (which compiles every tag pattern with Go's regexp).

Open the pull request with the `product-request` label and link the pages you verified the sources on.

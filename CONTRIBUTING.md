# Contributing

Thanks for helping. The most valuable contributions are curated notes and catalog entries; code is welcome too.

## Curated notes

A curated note explains what an advisory means for a self-hosted setup and what to do. Notes are written by the community and reviewed by the maintainer before they count.

1. Open a [curated note request](../../issues/new?template=curated-note.yml), or go straight to a pull request.
2. Add `notes/<advisory-id>.md` following [docs/adding-a-note.md](docs/adding-a-note.md), with `status: draft`.
3. The maintainer reviews it, may edit it, and sets `status: reviewed` with their name and the date. Only reviewed notes reach the feed and the notifier image.

Notes are licensed CC-BY-4.0 (see [notes/LICENSE](notes/LICENSE)); by opening the pull request you agree to that. Write notes yourself: do not paste vendor or community posts. Text drafted with an AI model is allowed only when the front matter says so (`authorship: model-drafted`) and must be checked by a human before review.

Found a note that is wrong? Use the [wrong note report](../../issues/new?template=wrong-note.yml).

## Products

Ask for a product with a [product request](../../issues/new?template=product-request.yml), or add it yourself: [docs/adding-a-product.md](docs/adding-a-product.md). The catalog stays small on purpose (quality over breadth), so say why self-hosters need it and where its advisories are published.

## Code

- Node.js 22.23.4 or newer, pnpm 10, Go 1.26 or newer.
- `pnpm install` sets up the Git hooks (Prettier, ESLint, gofmt and commitlint).
- Before a pull request: `pnpm validate && pnpm lint && pnpm typecheck && pnpm test`, and `go vet ./... && go test ./...` in `image/`.
- Commits follow Conventional Commits with a required scope: `type(scope): lowercase summary`. Scopes: catalog, schemas, ingest, matcher, site, image, notes, docs, ci, build, deps, repo, test.
- Changing a schema? Read [docs/feed-contract.md](docs/feed-contract.md) first, run `pnpm gen:types` and update the fixtures.

Security issues go through [SECURITY.md](SECURITY.md), not public issues.

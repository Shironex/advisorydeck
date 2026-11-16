# Advisorydeck

Security advisories for the software self-hosters run, with short human-reviewed notes on what an advisory means for a typical self-hosted setup, and a tiny notifier image that posts only the advisories that match what you run.

**Status: early development.** Nothing is published yet. This repository holds the data contract, the first catalog entries and placeholders for the parts that come next.

## How it will work

1. Scheduled jobs collect advisories from public sources (the CVE list, the GitHub Advisory Database, vendor feeds) for a curated catalog of products such as PostgreSQL, Traefik, Redis, Coolify and Docker Engine.
2. A static site publishes them, with a JSON feed under `api/v1/`.
3. You run a small container with a config file listing your products and versions. It polls the public feed, matches locally and posts to Discord, Slack or a generic webhook. It needs no Docker socket, and the feed host never learns what you run.

No accounts and no telemetry.

## Repository

| Path                | What                                                                                                                                                               |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `catalog/`          | One YAML file per product                                                                                                                                          |
| `schemas/v1/`       | JSON Schemas: the contract between all parts                                                                                                                       |
| `notes/`            | Curated self-hoster notes (CC-BY-4.0)                                                                                                                              |
| `fixtures/`         | Hand-made example data that every part tests against                                                                                                               |
| `packages/contract` | TypeScript types, validators and loaders for the contract                                                                                                          |
| `packages/ingest`   | Advisory collection (in progress)                                                                                                                                  |
| `apps/site`         | Astro static site (placeholder)                                                                                                                                    |
| `image/`            | Go notifier image (v0: polling, local matching, Discord, Slack and webhook delivery), see [docs/image.md](docs/image.md)                                           |
| `docs/`             | [Architecture](docs/architecture.md), [feed contract](docs/feed-contract.md), [adding a product](docs/adding-a-product.md), [adding a note](docs/adding-a-note.md) |

## Development

Requires Node.js 22.23.4 or newer, pnpm 10 and Go 1.26 or newer.

```sh
pnpm install
pnpm validate      # catalog, notes and fixtures against the schemas
pnpm lint && pnpm typecheck && pnpm test && pnpm build
cd image && go test ./...
```

## Disclaimer

Best effort and no warranty. A note here never replaces the vendor's advisory: always read it.

## License

Code: [MIT](LICENSE). Curated notes in `notes/`: [CC-BY-4.0](notes/LICENSE). Advisory data keeps the terms of its source; each advisory links its sources.

# Ingest test fixtures

Recorded upstream responses, so the ingest tests never touch the network. All were fetched on 2026-11-16.

| Path                          | What                                                                                                                                                                                                                                                                         |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cve/*.json`                  | Real CVE JSON 5 records from cvelistV5 (`credits` removed): PostgreSQL (CVE-2026-120154, CVE-2026-120153), Redis by GitHub_M (CVE-2026-25243), Coolify by GitHub_M (CVE-2026-59734, fetched on its own as a GHSA alias), and one record outside the catalog (CVE-2025-71466) |
| `cvelist/releases.json`       | A cut-down `GET /repos/CVEProject/cvelistV5/releases` page: two hourly releases, one end-of-day release                                                                                                                                                                      |
| `cvelist/*.zip`               | Release assets rebuilt with the same layout as the real ones from the records above: the midnight baseline (a zip holding `cves.zip`, which uses ZIP64 end records like the real one), an end-of-day delta and an hourly delta (`deltaCves/<id>.json`)                       |
| `ghsa/repo-*.json`            | Real `GET /repos/{owner}/{repo}/security-advisories` entries for Coolify (split over two pages to test the Link header), Traefik, moby and Redis, newest updated first; author, credit and collaborator fields removed                                                       |
| `ghsa/global-traefik-v3.json` | Real `GET /advisories?ecosystem=go&affects=github.com/traefik/traefik/v3` entries                                                                                                                                                                                            |
| `endoflife/postgresql.json`   | Real `GET https://endoflife.date/api/v1/products/postgresql`                                                                                                                                                                                                                 |

The advisories chosen cover the upstream quirks normalization handles; `fixtures/match/` at the repository root holds the ranges the matcher expects for several of them, and `test/normalize.test.ts` checks ingest against those.

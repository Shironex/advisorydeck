# Ingest

`packages/ingest` turns upstream advisory data into the files in `data/`. It runs by hand for now (`pnpm ingest`); a scheduled workflow comes with the site deploy.

## Running it

```sh
pnpm ingest --backfill            # first run: the cvelistV5 midnight baseline (about 650 MB, cached in .cache/ingest)
pnpm ingest                       # every later run: only what changed since the last one
pnpm ingest --offline             # no network: rebuild the outputs from data/sources
pnpm ingest --since 2025-11-16    # keep advisories first published on or after this date
pnpm ingest --skip ghsa           # skip a source (cve, ghsa, branches, kev, epss, nvd)
```

`GITHUB_TOKEN` is optional. Without it GitHub allows 60 API requests an hour, which is enough for an incremental run (one request per catalog query plus a few release listings); the page count per query is capped lower and a capped query keeps its cursor. With a token the limit is 5000. The token is only ever sent to `api.github.com`. A rate limit that resets within a minute is waited out; a longer one stops that source, keeps its cursor and still writes a consistent feed from what is stored (the run exits 1).

## Sources

| Source                                                            | Read through                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Terms                                                            |
| ----------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| CVE records, [cvelistV5](https://github.com/CVEProject/cvelistV5) | GitHub releases: the hourly delta zip (`<day>_delta_CVEs_at_<HH>00Z.zip`, every record changed since that day's midnight baseline), the end-of-day delta (`<day>_delta_CVEs_at_end_of_day.zip`, release `cve_<day>_at_end_of_day`) and, for `--backfill`, the midnight baseline (`<day>_all_CVEs_at_midnight.zip.zip`, a zip holding `cves.zip`). Releases are kept for about six weeks; a cursor older than that needs `--backfill`. A CVE that a GHSA names but no delta brought in is fetched on its own from `raw.githubusercontent.com`. | [CVE Program Terms of Use](https://www.cve.org/Legal/TermsOfUse) |
| GitHub security advisories                                        | REST API: `GET /repos/{owner}/{repo}/security-advisories` for every `ghsa-repo` source, `GET /advisories?type=reviewed&ecosystem=&affects=` for every `ghsa-package` source, newest updated first, down to the stored cursor                                                                                                                                                                                                                                                                                                                  | CC-BY-4.0                                                        |
| Release branches                                                  | [endoflife.date API v1](https://endoflife.date/docs/api/v1/) for products with `branches.source: endoflife`                                                                                                                                                                                                                                                                                                                                                                                                                                   | MIT                                                              |
| CISA Known Exploited Vulnerabilities                              | The JSON feed `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`, else its mirror in [cisagov/kev-data](https://github.com/cisagov/kev-data). The whole catalog (CVE id and date added) is kept, about 1 800 entries, so offline runs check every CVE                                                                                                                                                                                                                                                      | CC0-1.0                                                          |
| EPSS, [FIRST](https://www.first.org/epss/)                        | The lookup API `https://api.first.org/data/v1/epss?cve=...` for the CVE ids of the feed only, in batches of at most 100 ids and 1900 characters, once every 20 hours (missing ids on every run). The API is meant for lookups like this; the daily full CSV is not needed                                                                                                                                                                                                                                                                     | Free, attribution requested                                      |
| NVD API 2.0                                                       | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=` for CVEs that neither the CNA nor GitHub scored: at most 20 a run, 6 seconds apart (no API key), a record without metrics is asked again after 7 days                                                                                                                                                                                                                                                                                                                               | NVD terms of use (not endorsed by NVD)                           |

Attribution for all of them is in [NOTICE](../NOTICE), and every advisory lists its records under `sources` with the license they are used under.

## What it writes

| Path                                                            | What                                                                                                                                 | Committed |
| --------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ | --------- |
| `data/advisories/<id>.json`                                     | One advisory per cluster (`schemas/v1/advisory.schema.json`)                                                                         | yes       |
| `data/api/v1/manifest.json`, `data/api/v1/products/<slug>.json` | The feed exactly as published ([feed-contract.md](feed-contract.md)); the site copies `data/api/v1/` to `api/v1/`                    | yes       |
| `data/quality.json`                                             | Per advisory, the judgement calls made on messy upstream data (see below)                                                            | yes       |
| `data/sources/{cve,ghsa,endoflife}/`                            | Trimmed upstream records: only the fields ingest reads, no reporter names                                                            | yes       |
| `data/sources/kev/catalog.json`                                 | The KEV catalog: version, release date and the date each CVE was added                                                               | yes       |
| `data/sources/epss/scores.json`                                 | The EPSS score, percentile and date of every CVE in the feed (pruned to the feed)                                                    | yes       |
| `data/sources/nvd/<id>.json`                                    | NVD CVSS metrics for the CVEs that needed them (pruned to the feed)                                                                  | yes       |
| `data/state.json`                                               | The published floor and the cursors (last cvelistV5 release applied, newest `updated_at` per GHSA query, when EPSS was last fetched) | yes       |

Every run rebuilds the outputs from `data/sources`, so the outputs are a function of the stored records, the catalog and `notes/`. Files are written only when their bytes change, JSON keys follow the schema order, advisories are sorted newest published first then by id, and `generated_at` / `updated_at` move only when the product file they describe changes. A rerun with no upstream change leaves every byte as it was. `data/` is excluded from Prettier because the manifest etag is the sha256 of the exact bytes. `pnpm validate` checks `data/` with the same rules as the fixtures.

## Which product a record belongs to

The catalog's source index (`buildSourceIndex`) decides:

- **CVE records**: `cveMetadata.assignerShortName` must match a `cve-cna` source and an `affected[]` entry must match its `products` (and `vendor`, when set). Records from other assigners are only kept when a stored GHSA names them, for their CNA score and dates.
- **Repository advisories**: belong to the repository's product. When some entries name the product itself (no language ecosystem, for example `Docker Engine` or `redis-server`) or a package the catalog gives the product, only those count; Go module entries of moby (`v2.0.0-beta.28`) are another version line and are skipped. When no entry does, all entries count (Coolify files some advisories under `npm:coolify`).
- **Global advisories**: an entry counts for the product that claims its `ecosystem:package`.

## Ranges

- Leading `v` and spaces are dropped; a version that does not fit the schema's version pattern makes the whole product's list unknown (`ranges: []`), never half a list.
- `>= A, < B` is one range; a comma between ranges or a hyphen range (`26.0.0 - 29.8.1`) separates them; several bare upper bounds in a row (`<= v19.03.15, <= v20.10.27`) are one branch each, starting at the bound's `major.minor.0`. `> A` is read as `>= A`.
- CVE records: `version` plus `lessThan` gives `introduced` and `fixed`, `lessThanOrEqual` gives `last_affected`, a range inside the version field (`< 8.6.3`) is parsed as above. PostgreSQL's `0 lessThan 14.25` stays `introduced: "0"`.
- GHSA: a single patched version fills an open range. When it is later than the written upper bound (`< v4.0.0-beta.436` patched in `4.0.0-beta.437`, `<= 4.0.0-beta.448` patched in `4.0.0-beta.451`), the range ends at the patched version: the stricter reading, so a version in between is reported affected rather than silently not affected. A bare version next to a later patch (`v4.0.0-beta.428`, patched `4.0.0-beta.429`) means every version before the patch. A bare version later than its patch (`v4.0.0`, patched `4.0.0-beta.469`) is unknown.
- GHSA `All` with one patched version per branch (`6.2.20, 7.2.11, 7.4.6, 8.0.4, 8.2.2`) becomes one range per branch: the first from `0`, each next from `x.0.0` on a new major (so an unpatched `7.0` line is covered) or `x.y.0` within a major. `All` or `TBD` alone carries no range: unknown.
- A Go module with a major suffix only holds that major: an open lower bound on `github.com/traefik/traefik/v2` starts at `2.0.0`, so Traefik 1.x users get no false alarm.
- Within a cluster, each product takes its ranges from the most trusted source in catalog order whose ranges are all bounded, else the most trusted one with any ranges, else unknown. For Redis this prefers a GHSA per-branch list over the CVE record's single `< 8.6.3`, and the CVE range over a GHSA that says `All`.

Each of these judgement calls on a real record is listed in `data/quality.json`, so a reviewer can check them against the vendor page.

## Clusters and fields

- GHSA records link to their CVE (`cve_id`, `identifiers`); linked ids form one cluster. The id is the lowest CVE id, else the GHSA id; every other id is in `aliases`.
- `title`: the CNA title, else the GHSA summary, else the first sentence of the description. `summary`: the CVE description, else the GHSA description (truncated to the schema limits).
- `severity`: the CNA's CVSS (3.1, then 4.0, 3.0, 2.0), else the GHSA's CVSS, else NVD's own (Primary) CVSS, else another NVD metric, else the GHSA severity word without a score, else `unknown`.
- `published_at` is the earliest of the cluster, `modified_at` the latest.
- `kev`: `listed` when any CVE id of the cluster is in the catalog, `added_at` the earliest date added, `checked: true` once the catalog was read. When no catalog was ever read (first run with KEV down, or `--skip kev` on an empty store), every advisory says `checked: false` and the run warns; `pnpm validate` refuses such a `data/`. A stored catalog is reused when a later fetch fails.
- `epss`: the highest score among the cluster's CVE ids, or `null` when EPSS has not scored any of them. Scores drift a little every day, so a stored score is replaced only when the percentile moves by 0.01, the probability by a tenth (and at least 0.001), or it crosses the 0.95 percentile. That keeps a daily run from rewriting every file.
- `revision` hashes severity level, ranges, `kev.listed`, the EPSS signal (only whether the percentile is 0.95 or above) and the note, so filling or refreshing a score does not repost anything.
- `sources` adds a `kev`, `epss` or `nvd` record for each CVE id the enrichment used.
- `note` is the reviewed note in `notes/<id>.md`, if any (`toFeedNote`).

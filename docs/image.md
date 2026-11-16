# The notifier image

A small Go daemon that polls the published feed, matches it against the products you run, and posts what affects you to Discord, Slack or a generic JSON webhook. It needs no Docker socket and no account, and the feed host never learns what you run: the image only downloads public files and matches locally.

Status: v0. No image is published yet: build it yourself.

## Quick start

```sh
docker build -t advisorydeck:local image/
cp docs/examples/.env.example .env              # then paste your real webhook URL into .env
cp fixtures/image/advisorydeck.yml advisorydeck.yml   # edit products, feed URL and channels
docker compose -f docs/examples/compose.yml run --rm advisorydeck once -dry-run
docker compose -f docs/examples/compose.yml up -d
```

The example [compose.yml](examples/compose.yml) runs the container with a read-only root filesystem, no capabilities, `no-new-privileges`, the non-root user 65532 and a named volume for its state.

## Commands

| Command                                                     | What it does                                                                                                                                                    |
| ----------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `advisorydeck run [-config path]`                           | The daemon (the image's default command). Polls every `poll_interval` (plus up to 10% jitter) and at digest time.                                               |
| `advisorydeck once [-config path]`                          | One poll and send, then exit. Exit code 1 when the feed could not be read.                                                                                      |
| `advisorydeck once -dry-run`                                | Prints what would be sent per channel. Reads the state (so it shows what this install would really send), sends nothing, writes nothing, needs no webhook URLs. |
| `advisorydeck run -replay-backlog` / `once -replay-backlog` | On a channel's first start, posts the open advisories (bundled) after the summary instead of only summarizing them.                                             |
| `advisorydeck once -digest-now`                             | Sends the digest now instead of waiting for `digest.time`. Handy to test a channel.                                                                             |
| `advisorydeck healthcheck [-config path]`                   | Exit 0 when the last successful poll is within three poll intervals plus five minutes. Used by `HEALTHCHECK`.                                                   |
| `advisorydeck check-config [-config path]`                  | Validates a config file.                                                                                                                                        |
| `advisorydeck version`                                      | Prints the version.                                                                                                                                             |

The config path defaults to `/config/advisorydeck.yml`. The format is [schemas/v1/image-config.schema.json](../schemas/v1/image-config.schema.json); examples are in [fixtures/image/](../fixtures/image/).

## Webhook URLs

A webhook URL is a password: anyone who has it can post to your channel. The config file never holds one. Each channel names an environment variable (`url_env`), and the image reads the URL from it at start. A missing or malformed variable stops the image with a message naming the variable, never its value. Discord and Slack URLs must use `https://`; a generic webhook may use `http://` for a receiver on your own network.

Logs are JSON lines on stderr and never contain webhook URLs: channels are named by type, `url_env` and `name`, and network errors are stripped of the URL before logging. Set `ADVISORYDECK_LOG_LEVEL=debug` for more detail.

## What gets sent

For each watched product the image asks the matcher about every advisory in the product file:

- **affected**: notified, with the reason and the fix to take (for a branch such as `17`: "branch 17 is affected before 17.12; if you run a floating tag, pull again and recreate the container").
- **unknown** (the feed has no ranges, or the version cannot be compared): notified as "check manually". The image never turns an unknown into "not affected".
- **not affected**: skipped.

Then the noise rules:

1. **Severity floor**: the advisory's level must reach `min_severity`. `unknown` (or a level this build does not know) never passes the floor on its own.
2. **Bypass rules** post instantly, whatever the floor and the mode:
   - the advisory is in CISA KEV (`kev.listed`, exploited in the wild). An advisory whose KEV status was not checked (`kev.checked` false or missing) is never treated as listed, and messages say "CISA KEV not checked", never "not in CISA KEV";
   - its EPSS percentile is 0.95 or above (in the top five percent of likely exploitation);
   - a reviewed note says a default setup is exposed (`exposure: default-exposed`). The v1 feed has no explicit "action required" flag, so this is the stand-in.
3. **Release bundles**: matches for one product are grouped by the release that fixes the declared version. One message per bundle names that release, the highest severity, a count per level and the advisory list (collapsed to "and N more" past the channel's limits). Advisories without a known fix are bundles of one, with "check manually".
4. **Branches collapse to one action**: for a branch declaration such as `17`, every bundle says the same thing: "make sure you run 17.13 or later" (the newest fix in the branch). A bundle for an older release than the newest one is recorded as sent without posting, because running the newest release covers it, unless it is urgent (KEV, EPSS, exposed by default). An exact version (`17.4`) gets "upgrade from 17.4 to X or later". Several bundles of one product that are due at the same time (a vendor publishing a batch) go out as one message.
5. **First start**: the first time a channel runs (empty state), it gets one summary message instead of the backlog: per product how many advisories are open at the floor, across how many releases, the one action to take, anything urgent and anything to check manually. Everything summarized counts as sent, so only new and revised advisories follow. Start with `-replay-backlog` to post the bundled backlog after the summary.
6. **Mode**:
   - `instant`: every bundle is posted when first seen.
   - `digest` (default): one message per channel at `digest.time` in `digest.timezone`, grouped by product (one section per product with one line per release); urgent bundles still post instantly (and are not repeated in the digest). The first digest after a fresh start comes at the next digest time.
   - `both`: every bundle is posted instantly and also listed in the digest.
7. **Once per revision**: each channel remembers the advisory `revision` it received, separately for instant posts and digests. A bundle is posted again only when one of its advisories is new or has a new revision (marked "new" or "revised" in the list), which the feed does only on material changes (severity, ranges, a KEV listing, EPSS crossing the 0.95 percentile, reviewed note).

Measured on the committed 12-month feed at `high`, the example config posts one summary on first start instead of 60 messages, and PostgreSQL drops from 59 instant messages in a year (34 in one week) to 4. The replay is `image/internal/engine/replay_test.go`; run it with `ADVISORYDECK_REPLAY_REPORT=1 go test ./internal/engine -run TestReplay -v` to print the table.

## State and the feed cache

Everything the image writes goes to the folder of `state_path` (default `/data`):

- `state.json`: the manifest's HTTP ETag, the time of the last successful poll, and per channel the revisions already sent, when the channel started (its first-start summary), the last digest time, and whether the webhook was disabled. The file is versioned: version 1 files from earlier images are moved to version 2 on read, with the channel counted as started, so an upgrade sends no summary and resends nothing. A file from a newer image is refused rather than overwritten. Written atomically (temporary file, then rename), saved after every successful send, so a restart or crash never resends.
- `feeds/`: the last manifest and the product files you watch, so a `304 Not Modified` still has data to match and a restart downloads nothing that did not change.

Mount a volume there. Nothing else in the container is written, so the root filesystem can be read-only.

## Polling

1. `GET manifest.json` with `If-None-Match` (the ETag from the last answer). A `304` means nothing changed.
2. For each watched product whose manifest `etag` differs from the cached file, `GET products/<slug>.json`.
3. The file's `sha256:` must equal the manifest etag. If not (the deploy was caught half way), the old copy is kept and the next poll tries again.
4. A feed whose `generated_at` is older than 48 hours is logged as stale.

## Delivery

Each webhook has its own queue: messages to one webhook go out one at a time and in order, while different webhooks proceed in parallel.

| Answer                 | What the image does                                                                                                                                                                                                                                                                               |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 2xx                    | Sent. Discord's `X-RateLimit-Remaining: 0` with `X-RateLimit-Reset-After` makes the next message wait for the bucket to reset.                                                                                                                                                                    |
| 429                    | Waits for `retry_after` (Discord's JSON body) or the `Retry-After` header, then retries. A wait longer than 10 minutes gives up until the next poll.                                                                                                                                              |
| 401, 403, 404, 410     | The webhook is deleted or the URL is wrong. The channel is **disabled** and logged as an error naming its `url_env`; nothing else is sent to it. Discord restricts IPs that keep calling dead webhooks. Put a working URL in the variable and restart: a different URL enables the channel again. |
| Other 4xx              | The message is dropped and logged (retrying cannot help); the channel stays enabled.                                                                                                                                                                                                              |
| 5xx or a network error | Exponential backoff with jitter (2 s doubling, at most 2 min), up to 6 attempts. Then the rest of that queue waits for the next poll; nothing is marked as sent.                                                                                                                                  |

### Discord

One embed per advisory: severity, product and your version in the title, the advisory link, the summary, fields for your version and the reason, fixed versions, severity and score, exploitation (KEV, EPSS), the reviewed note's exposure **with its assumptions** and its steps, and a footer with the data sources and the reviewer. Every message stays within Discord's limits (title 256, description 4096, 25 fields, field value 1024, footer 2048, 10 embeds and 6000 characters per message); a long digest is split over several messages. `allowed_mentions` is empty and `@everyone`/`@here` in third-party text is defused, so a message can never ping anyone.

### Slack

An incoming webhook message with Block Kit: one section per advisory with the same facts, a context line with the IDs and sources, and a divider. Text is escaped for Slack (`&`, `<`, `>`), digests are split to stay under 50 blocks per message.

### Generic webhook

A JSON `POST` for ntfy, Gotify, n8n or your own receiver. `items` always lists every advisory the message covers: an instant post carries one bundle (`bundle`, or `bundles` when several releases of one product are due together), a digest carries `bundles` for all of them, and the first-start summary has `kind: "summary"` with a `summary` object. Within v1, fields may be added but are never renamed or removed.

```json
{
  "schema": "advisorydeck/v1/notification",
  "kind": "instant",
  "sent_at": "2026-11-16T08:00:00Z",
  "items": [
    {
      "advisory_id": "CVE-2026-120154",
      "aliases": [],
      "title": "PostgreSQL INSERT ... ON CONFLICT can read rows despite row security policies",
      "summary": "...",
      "url": "https://www.postgresql.org/support/security/CVE-2026-120154/",
      "product": "postgresql",
      "product_name": "PostgreSQL",
      "declared_version": "17",
      "verdict": "affected",
      "reason": "branch 17 is affected before 17.12; if you run a floating tag, pull again and recreate the container, or upgrade to 17.12 or later",
      "urgent": "",
      "severity": { "level": "medium", "score": 4.3, "vector": "CVSS:3.1/...", "source": "cna" },
      "kev": false,
      "kev_state": "not-listed",
      "epss": { "score": 0.00295, "percentile": 0.22351, "date": "2026-11-15" },
      "fixed_in": ["18.7", "17.12", "16.16", "15.20", "14.25"],
      "fix": "17.12",
      "published_at": "2026-11-12T14:15:29.579Z",
      "revision": "sha256:...",
      "note": null
    }
  ],
  "bundle": {
    "key": "postgresql|fix:17.12",
    "product": "postgresql",
    "declared_version": "17",
    "fix": "17.12",
    "latest": "17.12",
    "action": "Make sure you run 17.12 or later. On the floating 17 tag, pull the image again and recreate the container.",
    "advisories": ["CVE-2026-120154"],
    "highest": { "level": "medium", "score": 4.3, "vector": "CVSS:3.1/...", "source": "cna" },
    "urgent": ""
  }
}
```

When the catalog marks a product's upstream as archived, every message for it (instant, digest and the first-start summary) puts `[UPSTREAM ARCHIVED]` after the product name and starts with one warning line (when it was archived, that no further fixes are expected, and the catalog's note); the webhook payload carries the same object as `upstream` on each bundle, item and summary product.

The summary object: `min_severity`, `mode`, `backlog` (true when the backlog follows) and `products[]` with `product`, `product_name`, `declared_version`, `branch`, `missing` (no file in the feed), `advisories` (in the feed for the product), `open` (ids at the floor), `releases`, `latest`, `action` and `highest`.

`verdict` is `affected` or `unknown`; `fix` is the release that fixes the declared version (empty when unknown or unfixed) and `fixed_in` every fix in the advisory; `urgent` is `""`, `kev`, `epss` or `action-required`; `kev` is true only when listed and `kev_state` is `listed`, `not-listed` or `not-checked`; `severity`, `epss` and `note` have the same shape as in the [product feed](feed-contract.md); `note` is null unless a reviewed note exists.

## Matching

The daemon asks the matcher in `image/internal/match` (described in [architecture.md](architecture.md#where-version-matching-lives)) through a small interface in `image/internal/matching`: given the declared product and version (and, later, an image) and one advisory, it answers affected, not affected or unknown, with a one-line reason, a stable reason code, and the release that fixes the declared version. For a branch such as `17` that is the highest fix inside the branch, the release a floating tag has to be pulled at. Tests can swap in any implementation with `matching.Func`.

## The container

- Static binary (`CGO_ENABLED=0`) on `gcr.io/distroless/static-debian12:nonroot`: CA certificates and time zone data are built in, there is no shell or package manager.
- Runs as user 65532. `/data` is created owned by that user, so a fresh named volume is writable.
- Only `/data` is written: run it with `read_only: true`.
- No Docker socket, no published ports, outbound HTTPS only (the feed and your webhooks).
- `HEALTHCHECK` runs `advisorydeck healthcheck` every 5 minutes after a 2 minute start period. A feed that cannot be read for three poll intervals marks the container unhealthy.

# Deploying the site and the feed

The site (`apps/site`) and the v1 feed are static files on GitHub Pages, built and deployed by [.github/workflows/site.yml](../.github/workflows/site.yml). The default address is the project Pages URL:

- Site: `https://shironex.github.io/advisorydeck/`
- Feed for the notifier image: `https://shironex.github.io/advisorydeck/api/v1/`

The image accepts a feed URL with a path before `/api/v1/` (the config schema only requires `https://` and the `/api/v1/` ending, and the image joins file names onto that base), so the project URL works as is.

## One-time repository settings

The workflow cannot turn these on itself:

1. **Settings > Pages > Build and deployment > Source: GitHub Actions.** This also creates the `github-pages` environment the deploy job uses.
2. **Custom domain: none** for now. To move to one later, set it in the same place, then set the build variables `SITE_URL` (for example `https://advisories.example.org`) and `SITE_BASE=/` in the workflow's build step; the generator writes the feed URL from them.
3. Settings > Actions > General: workflow permissions can stay at "Read repository contents". The workflow asks for what it needs per job (`actions: write` to keep its schedule alive, `pages: write` and `id-token: write` to deploy).

Then run it once by hand: Actions > Site > Run workflow.

## What a run does

1. Restores the ingest data from the previous run (Actions cache), or starts from the data committed on `main`.
2. `pnpm ingest` fetches only what changed since the stored cursors. Exit code 1 (a source was rate limited or unreachable) is a warning: ingest still writes consistent files from what it has.
3. `pnpm validate` checks catalog, notes and data against the schemas. A failure stops the run: nothing invalid is ever published.
4. If the data changed, it is saved to the cache for the next run and uploaded as the `ingest-data` artifact (kept 7 days).
5. A fingerprint of everything the site is built from (data, notes, catalog, schemas, contract, site code, lockfile) is compared with the last deploy. Unchanged means no build and no deploy.
6. Otherwise the site is built (the build copies `data/api/v1/` to `api/v1/` byte for byte and checks every etag) and deployed to Pages.

Manual runs take three switches: `force_deploy` (deploy even if unchanged), `skip_ingest` (rebuild from stored data) and `backfill` (re-read the cvelistV5 baseline, needed when the stored cursor is older than the roughly six weeks of releases cvelistV5 keeps).

## Why the workflow never commits

`main` is protected: pull requests only, with required checks. A bot commit of fresh data would be rejected, so the live data lives in the Actions cache and in the deployed site. The data committed on `main` is the seed and the reviewable history. To refresh it, download the latest `ingest-data` artifact (or run `pnpm ingest` locally) and open a pull request. Do that at least every five weeks or so: when the cache is gone (unused for 7 days, or the committed data, ingest code or catalog changed), a run starts again from the committed cursor, and a cursor older than about six weeks needs a `backfill` run.

## Minutes

Each hourly run installs dependencies (cached), runs ingest and validation, and only builds and deploys when something changed: about one to two minutes, so roughly 1,000 to 1,500 minutes a month. Standard GitHub-hosted runners are free for public repositories. To spend less, change the `cron` line (for example `23 */2 * * *` for every two hours); the notifier image allows for quiet periods (it warns when the feed is older than 48 hours).

## The 60 day rule

GitHub disables scheduled workflows in a public repository after 60 days without repository activity. Ingest cannot create activity by committing (see above), so:

- Every scheduled run calls the "enable workflow" API for itself (`PUT /repos/{owner}/{repo}/actions/workflows/site.yml/enable`). It is one cheap API call. Whether GitHub counts this as activity and resets the 60 day clock is not documented; tools such as keepalive-workflow rely on it, but treat it as best effort.
- Any normal repository activity (a push, a merged pull request) resets the clock anyway, and refreshing the committed data every few weeks (above) is such activity.
- If the schedule does get disabled: Actions > Site > Enable workflow, or `gh workflow enable site.yml`. A stale feed shows: the site footer prints when the feed data was last updated, and the notifier image logs a warning when `generated_at` is older than 48 hours.

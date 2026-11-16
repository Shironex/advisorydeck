# Advisorydeck site design brief (approved by the owner 2026-11-16)

Product context: PRODUCT.md next to this file (register: product).

1. Feature: the Advisorydeck website. Free public feed of security advisories for self-hosted software by category and product, plus a client-side generator for the notifier's config. For self-hosters arriving from a search, Discord or a notification.
2. Primary action: on a product page, see within seconds whether my version is affected and which release fixes it; then go to the generator.
3. Direction:
   - Color strategy Restrained. Warm graphite neutrals (not the blue-black security reflex), one cool verdigris accent for links and actions only.
   - Severity scale critical / high / medium / low / unknown, always text label plus shape (critical diamond, high triangle, medium dot, low ring, unknown dashed ring), color only supports it.
   - Scene: a self-hoster in an evening homelab session in a dim room checking whether today's advisory hits their Postgres. DARK designed first, light matched. Site follows the system setting with a toggle.
   - Anchors: Linear changelog and docs (quiet type, rhythm), Stripe docs (code blocks, generator), GitHub advisory structure (ranges, patched versions).
   - Type: Geist (UI) and Geist Mono (versions, IDs, config), Google Fonts. One sans, tight product scale (about 12/13/15/17/20/26).
4. Scope: high-fi static mockups of 4 pages (feed home, product page, advisory page, generator), each dark and light, plus phone (390 px) views. Tokens handed to the site build.
5. Layout: docs shell, top bar (wordmark, search with "/" hint, Feed, Products, Generator, Sources, theme toggle), side nav by category then product with counts.
   - Home: chronological feed grouped by day; each row severity, product, ID, title, the fix. Release bundles (several advisories fixed by one release) collapse into one row with "show all".
   - Product: answer first: "check your version" input with result, then an affected-per-branch table (branch, supported until or end of life, latest release, advisories fixed in the last 12 months), then the advisory list.
   - Advisory: answer block first (affected ranges per branch and the fix), then details with a source on every field (severity with its source, KEV, EPSS, CWE, dates), the curated note in its state (none / draft clearly labelled / reviewed with reviewer and date, assumptions shown next to any exposure label), data-quality notes, sources and licenses, "report a wrong note" link.
   - Generator: two columns: form left (products with version and "exact version vs I pull the floating tag" choice, min severity, mode instant/digest/both with time and time zone, channels Discord/Slack/generic with env var names only), live output right in tabs advisorydeck.yml / compose.yml / .env, schema-valid indicator, copy and download, "runs in your browser, nothing is sent".
6. States to show somewhere: draft vs reviewed note, KEV "not checked", unknown affected status, end-of-life branch, empty product, stale feed warning, generator validation error.
7. Content: real data from the committed feed (see below), no invented numbers presented as facts, no em or en dashes.
8. Not doing: no hero, no stat tiles, no charts, no glow, no neon, no card grids, no side-stripe borders, no gradient text.

## Real data to use (from ~/Documents/Projects/advisorydeck/data/api/v1, read it for more)

- Feed generated 2026-11-16 00:22 UTC, 238 advisories, 5 products: PostgreSQL 96 (databases), Redis 3 (databases), Traefik 70, Docker Engine 8, Coolify 61.
- PostgreSQL branches: 18 (supported until 2030-11-14, latest 18.7), 17 (2029-11-08, 17.12), 16 (2028-11-09, 16.16), 15 (2027-11-11, 15.20), 14 (end of life 2026-11-12, 14.25), older all EOL. Advisories in the last 12 months touching each branch: 18: 96, 17: 86, 16: 81, 15: 77. PostgreSQL severities: high 66, medium 24, low 6. Version 17.10 is affected by 72 advisories, fixed by 17.11 or 17.12.
- CVE-2026-6460, 12 Nov 2026, high 8.8, CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H, source CNA, CWE-843, "PostgreSQL type confusion after ALTER ... SET DATA TYPE executes arbitrary code", fixed 18.7, 17.12, 16.16, 15.20, 14.25; KEV not checked yet; EPSS none; source cve.org (CVE Terms of Use) and postgresql.org/support/security/CVE-2026-6460/.
- Also 12 Nov: CVE-2026-6467 high 7.2, CVE-2026-18447 high 8.8 (same PostgreSQL release); Traefik GHSA-x5pf-cqh3-2gv8 high 8.7 (Compress middleware zstd memory DoS, fixed 3.7.18), GHSA-rr42-h8r2-f28g medium 6.3 (BasicAuth MD5-crypt CPU, fixed 2.11.62 / 3.7.18).
- 10 Nov: Docker Engine CVE-2026-115538 high 7.0 (overlay encryption rules not restored after firewalld reload, fixed 29.9.3).
- Coolify 2 Jul: CVE-2026-34037 critical 9.9 (cross-tenant cloning, fixed 4.0.0-beta.464), CVE-2026-34035 high 8.8 (log drain command injection, fixed beta.466).
- Example generator config: fixtures/image/advisorydeck.yml in the repo; feed URL https://shironex.github.io/advisorydeck/api/v1/.

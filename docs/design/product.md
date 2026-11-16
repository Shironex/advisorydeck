# Product

## Register

product

## Users

Self-hosters first: people who run a homelab or a few VPSes with Postgres, Redis, Traefik, Docker and Coolify. They arrive from a search, a Discord link or a notification and want one answer fast: "am I affected, and what do I pull or upgrade to?" Then they set up the notifier with the generator so they do not have to check again. Feed readers who scan the latest advisories across products are a secondary audience.

## Product Purpose

Advisorydeck is a free, open feed of security advisories for self-hosted software, organised by category and product, with affected and fixed versions per release branch, plus a small Docker image that posts only the advisories that match what you run to Discord, Slack or a webhook. A client-side generator writes its config. Success: a self-hoster finds their product, reads whether their version is affected and which release fixes it in under a minute, and leaves with a working config.

## Brand Personality

Calm, exact, trustworthy. Reads like a well-kept logbook: no alarmism, every claim shows its source, severity stated plainly, drafts clearly labelled as drafts. Quiet, typographic confidence in the lane of Linear's changelog and docs and Stripe's docs.

## Anti-references

- Dark neon "hacker" looks: green on black, glitch effects, skulls, red alarm walls.
- SaaS marketing landings: hero with big numbers, gradient blobs, feature card grids, sign-up pushes.
- Grafana-style dashboards: widget walls, charts for the sake of charts.

## Design Principles

- Answer first: every product and advisory page leads with "affected or not, and the fix", before prose.
- Show the source: every severity, range and note carries where it came from and when.
- Calm severity: severity is legible without shouting; color supports text, never replaces it.
- Earned familiarity: standard docs patterns (top bar, side nav, tables, breadcrumbs) over novelty.
- Honest uncertainty: unknown, unchecked and draft states are shown as such, never as safe.

## Accessibility & Inclusion

WCAG 2.2 AA. Full keyboard use with visible focus, landmarks, contrast 4.5:1 for text including small labels, severity and status never conveyed by color alone (text label plus shape), reduced motion respected, readable at 320 px.

# Adding a curated note

A curated note tells a self-hoster, in a few sentences, whether an advisory touches a typical self-hosted setup and exactly what to do. It is the part of Advisorydeck that a CVE bot cannot provide, so it is held to a high bar.

## Rules

- Read the vendor advisory first and link nothing you have not read. The note supplements the advisory; it never replaces it.
- Write it yourself, in plain English. Do not copy vendor or community posts.
- Never write "low risk" or "safe" on its own. The `exposure` label always comes with the `assumptions` it depends on.
- When you are unsure whether a default setup is exposed, use `exposure: unknown`.
- AI-drafted text must say so (`authorship: model-drafted`) and cannot be reviewed until a human has edited it (`model-drafted-human-reviewed`).

## Format

`notes/<advisory-id>.md`, where the id is the advisory's cluster id (the CVE id when there is one, else the GHSA id). Front matter schema: [schemas/v1/curated-note.schema.json](../schemas/v1/curated-note.schema.json). A complete example: [fixtures/notes/CVE-2026-120154.md](../fixtures/notes/CVE-2026-120154.md).

```markdown
---
advisory: CVE-2026-120154
products: [postgresql]
audience: generic-selfhosters # or coolify-selfhosters
exposure: not-default # default-exposed | conditional | not-default | unknown
assumptions:
  - No row security policies are used to hide rows from database roles.
actions:
  - kind: backup
  - kind: upgrade
    text: Move to the fixed minor release of your branch.
  - kind: commands
    code: |
      docker compose pull
      docker compose up -d
status: draft
authorship: human
written_by: your-github-name
---

Two or three sentences: who is affected, why a default setup is or is not, what to do.
```

Action kinds: `upgrade`, `backup`, `commands` (needs `code`), `config`, `restart`, `read`.

## Review

1. Open the pull request with `status: draft` and the `curated-note` label. Run `pnpm validate`.
2. The maintainer checks the note against the advisory, edits it if needed, then sets `status: reviewed`, `reviewed_by` and `reviewed_at`. Only then does it reach the site as reviewed and the notifier image at all.
3. If a reviewed note turns out wrong, anyone can file a [wrong note report](../../../issues/new?template=wrong-note.yml); the note becomes `disputed` (exposure hidden) until it is fixed.

The states are summarised in [notes/README.md](../notes/README.md).

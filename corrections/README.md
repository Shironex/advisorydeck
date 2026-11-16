# Hand corrections

Some upstream advisories carry a typo that makes current releases read affected: a bound of `< 26.37.1` next to the patched version `26.7.1`, or SDK version numbers listed under a runtime product. A correction replaces the ranges ingest read for one product of one advisory with the right ones, and says so on the advisory.

One YAML file per advisory and product: `corrections/<product>/<advisory-id>.yml`, for example `corrections/keycloak/GHSA-f8m4-v488-rmrm.yml`. The schema is [schemas/v1/correction.schema.json](../schemas/v1/correction.schema.json).

```yaml
advisory: GHSA-f8m4-v488-rmrm # any id of the advisory: the CVE id or the GHSA id
product: keycloak # the catalog slug, equal to the folder name
reason: >- # one or two plain sentences, written by a person, shown on the site
  The repository advisory writes the 26.7 bound as < 26.37.1 next to the patched version 26.7.1,
  a typo for < 26.7.1.
evidence: # the vendor release notes, the fix commit or the upstream issue
  - https://github.com/keycloak/keycloak/releases/tag/26.7.1
corrected_at: 2026-11-16
upstream_ranges: # what ingest published before the correction, copied from data/advisories/<id>.json
  - introduced: '0'
    fixed: 26.37.1
ranges: # the corrected ranges, in the order they are published
  - introduced: '0'
    fixed: 26.7.1
```

## Rules

- Correct only what the evidence shows: a vendor release note, a fix commit and the release that first ships it, or an upstream issue about the typo. Never correct a range because it looks too wide; ingest reads ambiguous data strictly on purpose.
- Every correction goes through a pull request, which is its review. Report the typo upstream too (the repository advisory or the CNA), so the correction can be removed once upstream fixes it.
- Ingest applies corrections after it has built every advisory, recomputes the advisory's `revision` (images notify again with the corrected ranges) and lists the correction under the advisory's `corrections`, with the reason, the evidence and what upstream said. The site shows it as a "Corrected by advisorydeck" notice next to the ranges.
- Stale corrections warn on every ingest run, in the run log and in `data/quality.json`, so they get removed: when the advisory is no longer in the feed, when it no longer names the product, or when upstream now reads the corrected ranges itself. When the upstream reading changed in another way, the correction is still applied and the warning asks for a recheck; update `upstream_ranges` once checked.
- `pnpm validate` checks each file against the schema, its folder and file name and the catalog, and that every correction published in `data/` matches its file.

## License

The corrections in this folder are licensed under [CC-BY-4.0](LICENSE), like the notes. The rest of the repository is MIT.

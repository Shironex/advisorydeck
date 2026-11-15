# Curated notes

One Markdown file per advisory: `notes/<advisory-id>.md`, for example `notes/CVE-2026-120154.md`. YAML front matter holds the structured fields, the body holds a few plain sentences. How to write one: [docs/adding-a-note.md](../docs/adding-a-note.md). The front matter schema is [schemas/v1/curated-note.schema.json](../schemas/v1/curated-note.schema.json).

## States

| `status`     | Meaning                                               | Site                                                             | Feed and image |
| ------------ | ----------------------------------------------------- | ---------------------------------------------------------------- | -------------- |
| `draft`      | Written, not reviewed yet                             | Shown greyed out, labelled "unreviewed draft, do not rely on it" | Never included |
| `reviewed`   | Checked by the maintainer, who is named with the date | Shown with reviewer and date                                     | Included       |
| `disputed`   | Reported wrong and under investigation                | Exposure hidden, banner shown                                    | Never included |
| `superseded` | Replaced by newer information                         | Shown as historical                                              | Never included |

A note marked `authorship: model-drafted` can never be `reviewed`: a human edits it first and changes authorship to `model-drafted-human-reviewed`.

The exposure label (`default-exposed`, `conditional`, `not-default`, `unknown`) is always shown with its assumptions; `conditional` and `not-default` require at least one assumption.

## License

The notes in this folder are licensed under [CC-BY-4.0](LICENSE). The rest of the repository is MIT.

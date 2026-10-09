# Contract: Hermie blocks in a reply

This directory is the written definition of the structured blocks a Hermie client draws in a bot's reply, and
the numbers the gateway's guide tells a model about them.

Files:

- `chart.schema.json`: JSON Schema (2020-12) of the object in a `hermie-chart` fence.
- `cards.schema.json`: JSON Schema (2020-12) of the object in a `hermie-cards` fence.
- `SHA256SUMS`: pins the files of this directory (`shasum -a 256 -c SHA256SUMS`).

The validators live in the clients; the gateway only tells a model what they accept
(`tui_gateway/hermie_markup.py`, one paragraph per block), and
`tests/tui_gateway/test_hermie_markup.py` reads these schemas and checks that every number the guide states
is the one here. The Hermie apps repository carries a byte-identical copy of this directory, completed there
with the icon vocabulary and the valid and invalid examples its validators read.

## Common rules

- A block is a fenced code block whose language is `hermie-chart` or `hermie-cards`, holding exactly one JSON
  object. Its text is at most 16 KiB of UTF-8 (`x-maxSourceBytes`), checked before parsing.
- A block that is not exactly the format is shown as code, never repaired. Unknown keys are refused
  everywhere.

## Rules a schema cannot state

`hermie-chart`: every `values` list is exactly as long as `x`; series names are unique; a trimmed empty
`title` or `unit` is no title or unit; numbers in `x` are written out as text and must not collide with
another category; a `pie` has values that are not negative, at least one above zero.

`hermie-cards`: titles are trimmed, an empty block title is no title; at most one card has
`highlight: true`; `next` is refused on the last card; `connector` and `next` are refused with
`layout: grid`; an `icon` that is not in the client's vocabulary draws a generic glyph instead of refusing
the block (the one lenient field).

## Callouts

GitHub alerts need no schema: a quote whose first line is exactly `[!NOTE]`, `[!TIP]`, `[!IMPORTANT]`,
`[!WARNING]` or `[!CAUTION]` (upper case, alone on the line) is drawn as a callout; any other quote stays a
quote.

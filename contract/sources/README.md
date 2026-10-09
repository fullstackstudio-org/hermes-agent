# Contract: the sources of a reply

This directory is the written definition of the pages a bot's reply used: the list the gateway attaches to
the reply when the turn searched the web or read pages, and how a Hermie client shows it.

Files:

- `schema.json`: JSON Schema (2020-12) of one reply's `sources` list (`Source` items). Rendered from the
  gateway's model (`tui_gateway/contracts/common.py`) by `scripts/gen_gateway_contracts.py`; never edit it by
  hand.
- `examples.json`: valid and invalid entries, a `message.complete` payload, a `session.history` row, and how
  tool results become a list.
- `SHA256SUMS`: pins the three files above (`sha256sum -c SHA256SUMS` or `shasum -a 256 -c SHA256SUMS`).

The source of truth is the gateway's repository. Other repositories carry a byte-identical copy of this
directory. In the gateway repository `python scripts/gen_gateway_contracts.py --check` rebuilds `schema.json`
and `SHA256SUMS` and compares them, and `tests/tui_gateway/contracts/test_sources_contract.py` checks every
example against the model and the gateway's collector.

Normative words: MUST, MUST NOT, SHOULD as in RFC 2119.

## 1. Where the list comes from

The gateway builds the list from the results of the turn's own web tools, never from the model's text:

- `found`: every result `web_search` returned (`data.web[]`: its `url` and `title`).
- `read`: every page `web_extract` fetched (`results[]` entries without an `error` and not blocked by policy).

Only results of the turn that the reply ends count. A page's content or description never leaves the gateway.

## 2. The list

- One entry per `url`. A URL both found and read is `read` (with the read page's title, or the found title
  when the read one is empty).
- Ordered: every `read` entry first, then the `found` ones; within a tier, in the order the tools returned
  them.
- At most 24 entries; the rest are dropped.
- `url`: `http` or `https`, with a host and no user info, at most 2048 characters, as the tool returned it
  (trimmed, not normalised). A result whose URL is anything else is left out.
- `title`: at most 160 characters, with control, format and invisible characters removed and whitespace
  collapsed. It may be empty. A page can claim any title: it is text, never markup.
- `via`: `read` or `found`.

## 3. Where a client finds it

- Live: `message.complete.sources`, beside `text`, on a turn that completed.
- After a reload: the reply's row in `session.history` (and the dashboard's message list) carries the same
  list as `display_metadata.sources`.
- Absent when the turn used no web tool or none of its results qualified. The gateway never sends `[]`.

A client MUST tolerate the key being absent and MUST ignore it when it does not read sources. A client that
reads it SHOULD check every entry against `schema.json` and drop the ones that fail, keeping the rest.

## 4. What a client does with it

- It MUST NOT load anything for an entry: no favicon, no preview, no request to the page or to a third party.
  A monogram (the domain's first letter) stands in for an icon.
- It MUST show the entry's domain beside its title, so a misleading title cannot hide where the link goes,
  and SHOULD let VoiceOver and other screen readers read the domain.
- It opens the URL only on the person's own tap, through its usual link policy.

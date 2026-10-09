# Contract: Hermie markup in a reply

This directory is the written definition of the structured blocks a reply can carry besides plain Markdown,
and of the one thing every client does with them: draw the block when it is exactly what this says, show the
text it came from when it is not.

Files:

- `cards.schema.json`: JSON Schema (2020-12) of the body of a `hermie-cards` block.
- `chart.schema.json`: JSON Schema (2020-12) of the body of a `hermie-chart` block, the format `docs/charts.md`
  describes (that page keeps the rules a schema cannot say).
- `icons.json`: the closed vocabulary of card icons: for each name, the SF Symbol the Apple apps draw and the
  outline the web draws (`svg`, one path's `d` attribute on a 24x24 grid, stroked with `currentColor`; it is
  path data, never markup). Plus the `generic` glyph an unknown name falls back to.
- `examples.json`: valid and invalid `hermie-cards` blocks, each invalid one naming the rule it breaks, and
  alert quotes, each saying whether it is an alert.
- `SHA256SUMS`: pins the five files above (`shasum -a 256 -c SHA256SUMS`).

This directory is authored in this repository, because the validators live in the clients. The gateway's
repository carries a byte-identical copy: its guide text, which tells a model the formats, states the caps of
both schemas, and a test there reads the schemas and `examples.json` and checks every number. The
`hermie-chart` block is older; `docs/charts.md` defines it and `chart.schema.json` restates it as a schema.

Normative words: MUST, MUST NOT, SHOULD as in RFC 2119.

## 1. Transport

A block is a fenced code block whose info string starts with `hermie-cards` (case does not matter; models
capitalise) holding one JSON object. A client draws it only when the fence is closed and the body validates
(section 3); every other case is the code block it is. The block stays a code block in the shared block model
(`contract/markdown`), so no other renderer changes and the worst case is that a reader sees the data instead
of the picture. A client MUST NOT repair a block: it is drawn exactly as sent or not drawn.

No block triggers a request. Nothing in a block is a URL, an image or markup: titles, subtitles, tags and
labels are text, and an icon is a name that resolves through `icons.json`, never a string handed to a symbol
loader or into an SVG.

## 2. The block

```json
{
  "title": "Hoe ik het zou opzetten",
  "layout": "stack",
  "connector": "arrow",
  "cards": [
    {
      "icon": "server",
      "title": "Gateway per klant",
      "subtitle": "k3s, eigen Postgres",
      "tags": ["k3s", "Postgres"],
      "highlight": true,
      "next": "deployt naar"
    },
    { "icon": "globe", "title": "Website", "subtitle": "Next.js standalone" }
  ]
}
```

| Key                 | Required | Rules                                                                                                                                   |
| ------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `title`             | no       | At most 120 characters. A line over the picture.                                                                                        |
| `layout`            | no       | `stack` (default): one card under the other. `grid`: cards side by side, wrapping.                                                      |
| `connector`         | no       | `arrow` (default), `line` or `none`: what joins a card to the next one. Only with `stack`.                                              |
| `cards`             | yes      | 2 to 12 objects.                                                                                                                        |
| `cards[].title`     | yes      | 1 to 60 characters.                                                                                                                     |
| `cards[].subtitle`  | no       | At most 140 characters.                                                                                                                 |
| `cards[].icon`      | no       | At most 32 characters; a name from `icons.json`, case does not matter. Any other name is the generic glyph (D3). No `icon` is no glyph. |
| `cards[].tags`      | no       | At most 6 strings of 1 to 24 characters, unique within the card.                                                                        |
| `cards[].highlight` | no       | Boolean. At most one card in the block.                                                                                                 |
| `cards[].next`      | no       | At most 40 characters: the label on the connector to the next card. Not on the last card, not with `grid`.                              |

## 3. Validation

The reader works in this order and stops at the first refusal; an example breaks exactly one rule.

1. The text is at most 16384 bytes of UTF-8, checked before anything is parsed (`tooLarge`).
2. It is JSON (`notJSON`) and the value is an object (`notAnObject`).
3. Keys are known, at the top and in every card: the first unknown one, in alphabetical order, is refused
   (`unknownKey`, `key` is the name).
4. `layout` (a string: `wrongType`; one of two: `unknownLayout`, `key` is the value), `connector` likewise
   (`unknownConnector`), a `connector` of any value with `layout` `grid` (`connectorNeedsStack`).
5. `title`, when present: a string (`wrongType`), trimmed, at most 120 (`labelTooLong`); empty is absent.
6. `cards`: present (`missing`, `key` `cards`), a list of objects (`wrongType`), 2 to 12 (`tooFewCards`,
   `tooManyCards`), counted before any card is read.
7. Each card, in order: `title` present (`missing`), a string (`wrongType`), trimmed, not empty (`emptyLabel`),
   at most 60 (`labelTooLong`). `subtitle`, `icon` and `next` are strings (`wrongType`), trimmed, at most their
   cap (`labelTooLong`, `key` is the name); empty is absent. `tags` is a list of strings (`wrongType`) of at
   most 6 (`tooManyTags`), each trimmed, not empty (`emptyLabel`, `key` `tags`), at most 24 (`labelTooLong`,
   `key` `tags`), unique after trimming (`duplicateTag`, `key` is the tag; case counts as a difference).
   `highlight` is a boolean (`wrongType`).
8. Across the cards: more than one `highlight: true` (`twoHighlights`); a non-empty `next` on the last card
   (`nextOnLastCard`) or with `layout` `grid` (`nextNeedsStack`).

A JSON `null` is the same as an absent key, for every optional key. Numbers are never turned into strings.
Lengths are counted in characters as a reader sees them (an extended grapheme cluster: a family emoji is one),
not in bytes or UTF-16 units. White space is trimmed from both ends before a length or emptiness is judged.

The result a client draws from is the normal form in each valid example's `expect`: `layout` and `connector`
defaulted (`connector` is absent with `grid`), `tags` always a list, `highlight` always a boolean, an absent
`title`, `subtitle` and `next` left out, and an `icon` that is absent left out, a vocabulary name as its
lower-case name, any other as `generic`.

## 4. Alerts

An alert is a quote that begins with one of five markers on a line of its own:
`[!NOTE]`, `[!TIP]`, `[!IMPORTANT]`, `[!WARNING]`, `[!CAUTION]`. The marker is upper case and exact; the rest
of its line may hold nothing but white space. The marker is not a block of its own: the parser still produces a
quote, so the shared block model and `contract/markdown` do not change, and a renderer that does not know the
marker shows a quote that begins with it. A renderer that does know it draws a callout (an icon, a tint, the
kind as its title) and drops the marker line; the rest of the quote is the callout's content. A marker with
nothing after it is a callout with a title only. A lower-case or mixed-case marker, text after the marker on
its line, a marker that is not the quote's first line, an unknown marker and a marker outside a quote are
ordinary text. A quote nested inside a callout is an ordinary quote.

Each alert in `examples.json` has the Markdown, the `alert` kind (lower case) or `null`, and for an alert the
`body` that is left once the marker line is gone.

## 5. Who draws what

A client draws a block only in a reply that is not the owner's own bubble: what the owner types stays as
typed. A client that cannot draw a block (an older build, another renderer) shows the code block. The gateway
is told which blocks a client draws through the `markup` capability; that belongs to the gateway protocol
and is not defined here.

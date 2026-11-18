# zig-mime

A streaming MIME parser for Zig. It walks nested multipart messages with bounded memory and decodes base64 and quoted-printable bodies straight into a sink. It tolerates the malformed input that real mail and HTTP uploads contain:
- bare LF line endings
- missing final boundaries
- duplicate boundaries
- deep nesting

Built for [Guardian](https://github.com/stacksjs/guardian)'s scanner and for the mail server, and shared with zig-waf's multipart handling where its compatibility evidence allows.

> Pre-alpha. Planned work is tracked as issues in this repository.

## Usage

A `Walker` is a push parser. Feed it chunks of any size and it calls your sink with events. It never allocates: its own state is a few kilobytes, and header blocks of the open parts live in a scratch buffer you provide.

```zig
const mime = @import("mime");

const Scanner = struct {
    pub fn onEvent(self: *Scanner, event: mime.Event) mime.Sink.Error!void {
        switch (event) {
            .part_begin => |part| {}, // part.content_type, part.headers, part.path, part.depth
            .body => |b| {}, // b.bytes, b.region (content, preamble, epilogue, unparsed)
            .part_end => |e| {}, // e.part, e.raw_bytes
            .diagnostic => |d| {}, // d.kind: a limit reached or a malformation tolerated
        }
        _ = self;
    }
};

var scanner: Scanner = .{};
var scratch: [64 * 1024]u8 = undefined;
var walker = mime.Walker.init(&scratch, mime.Sink.init(&scanner), .{});
while (try reader.next()) |chunk| try walker.feed(chunk);
try walker.finish();
```

- A `Part` and its header slices stay valid until that part's `part_end`.
- Body slices are only valid during the call.
- Return `error.Aborted` from `onEvent` to stop the walk.
- For an HTTP body, call `walker.beginWithHeaders("Content-Type: multipart/form-data; boundary=...")` before feeding. The stream then starts at the body instead of at a header block.

### Limits

`mime.Options` bounds the work per message:
- `max_depth` (16)
- `max_parts` (10,000)
- `max_header_bytes` per part (64 KiB)

Reaching a limit emits a diagnostic, and the bytes are still delivered (as an opaque leaf or as `unparsed` multipart bytes), so a scanner never loses content silently.

### Transfer decoding

Leaf bodies arrive decoded: base64 and quoted-printable are decoded on the fly, with partial quanta and escapes carried across chunks. Broken input is decoded as far as it goes rather than dropped. `PartEnd.decode_flags` says what was tolerated, and an `invalid_encoding` diagnostic reports invalid bytes or data after base64 padding. With `.raw_view = true` the undecoded body is delivered as well (`Body.raw`), so a scanner can check both views of a part whose encoding lies. The decoders are usable on their own as `mime.decode.base64.Decoder` and `mime.decode.qp.Decoder`.

### Headers

`part.headers` is the unfolded header block: `get(name)`, `count(name)` and `iterator()`, all without allocating. The walker also fills in the fields a scanner needs:
- `content_type`, `boundary`, `charset`, `encoding` and `disposition`
- `filename` and `name`, decoded to UTF-8: RFC 2231 extended values and continuations first, then RFC 2047 encoded words in a plain value, as clients do

Parameter parsing respects quoted strings and comments, so a `boundary=` hidden inside another parameter's quoted value is never picked up.

`mime.ContentType.parse` and `mime.validateBoundary` are ported from the mail server and pass its tests. A boundary that fails validation is reported as `boundary_invalid` and still used, because mail clients split on it. For the mail server's depth limit, set `.max_depth = 10`.

`mime.decodeWords` (RFC 2047) and `mime.decodeParam` (RFC 2231) decode other header text into a caller buffer. Supported charsets are UTF-8, US-ASCII, ISO-8859-1 and Windows-1252; other charsets are copied unconverted and flagged.

### Malformed input

Attackers hide attachments in the gaps between parsers, so where interpretations differ the walker takes the view that exposes the most content and reports a diagnostic. Each tolerance has a sample in `tests/evasion/` that must still yield its attachment:

| Input | Behaviour | Diagnostic |
|---|---|---|
| Bare LF or mixed line endings | Lines end at LF everywhere, including the header terminator | none |
| No close delimiter | Parts end at an outer delimiter or the end of input | `missing_close_delimiter` |
| Several `boundary` parameters, several Content-Type fields, RFC 2231 `boundary*` | Splits on every distinct boundary (`Part.boundaries`) | `conflicting_boundary`, `duplicate_header` |
| `boundary=` inside another parameter's quoted value | Ignored; quoted strings and comments are parsed | none |
| Delimiter with trailing garbage (`--bXYZ`) | Splits, as prefix-matching clients do | `boundary_suffix` |
| Parts after the close delimiter | The multipart is reopened | `part_after_close` |
| Nested multipart reusing the outer boundary | Innermost open multipart takes the delimiters | `nested_boundary_reuse` |
| Header block without a blank line | The first non-field line starts the body | `missing_header_separator` |
| base64 or quoted-printable on a multipart or message | Decoded and delivered as a leaf; walk it again to look inside | `encoded_container` |
| Duplicate Content-Transfer-Encoding | The decoding one wins; `raw_view` gives the other view | `duplicate_header` |
| Junk header fields pushing Content-* fields past the header limit | The first Content-Type, Content-Transfer-Encoding and Content-Disposition fields have a reserve | `header_too_large` |
| Duplicate filenames | `Part.filename` and `Part.filename_alt` | `conflicting_filename` |
| Overlong or invalid boundaries | Used anyway, up to 994 characters | `boundary_invalid` |
| Nesting or part count over the limits | Bytes delivered as an opaque leaf or `unparsed` bytes | `depth_exceeded`, `part_limit` |

Lines ending in a bare CR (old Mac OS) are not treated as line breaks.

## Planned features

- fuzz and differential tests

## Development

Zig `0.17.0-dev.1857+3c46da14d` (`pantry install` provides it from deps.yaml).

```sh
zig build test
zig build fuzz -Dfuzz-iterations=100000
zig build bench -- zig-out/bench.json
```

## License

MIT

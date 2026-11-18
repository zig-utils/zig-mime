# zig-mime

A streaming MIME parser for Zig. It walks nested multipart messages with bounded memory and decodes base64 and quoted-printable bodies straight into a sink. It tolerates the malformed input that real mail and HTTP uploads contain:
- bare LF line endings
- missing final boundaries
- duplicate boundaries
- deep nesting

Built for [Guardian](https://github.com/stacksjs/guardian)'s scanner and for the mail server, and shared with zig-waf's multipart handling where its compatibility evidence allows.

> Pre-alpha. Planned work is tracked as issues in this repository.

## Planned features

- SIMD boundary search over streamed input, with a nested multipart stack and depth limits
- streaming base64 and quoted-printable decoders
- header parsing with RFC 2047 and RFC 2231 decoding, plus ContentType and boundary validation
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

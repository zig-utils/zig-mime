# Changelog

## v0.1.1 - 2026-11-24

- chore: prepare the 0.1.1 release (9d14592)
- fix(build): fetch zig-bench only under -Dbench (c07c1c6)

## v0.1.0 - 2026-11-17

- chore: prepare the 0.1.0 release (c1e5348)
- fix: a CR held at a chunk boundary leaked into the body (1b7c398)
- test: fuzz targets and differential tests against the mail parser (2e4e572)
- fix: walker bugs found by fuzzing chunked against whole walks (c54e7b2)
- feat: evasion tolerance and an evasion corpus (5f7e604)
- chore: ignore the zig-pkg package cache (3f465ba)
- feat: header decoding with RFC 2047 and RFC 2231 (c939f3d)
- feat: streaming base64 and quoted-printable decoders (161b66c)
- feat: streaming MIME walker with SIMD boundary search (15a55bb)
- chore: scaffold zig-mime from zig-starter (1ef2d6d)
- chore: initial repository with plan and design (64c35bd)


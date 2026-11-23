# AGENTS.md

zig-mime is the streaming MIME parser shared by the Guardian scan engine (zig-utils/zig-anti-virus),
the mail server (mail-os/mail) and, where its compatibility evidence allows, zig-waf's multipart
handling. Its input is hostile mail and uploads.

- Work the lowest open `ready` + `guardian` issue (start: stacksjs/guardian#2); commit with `Closes #N`.
- Zig `0.17.0-dev.1857` (pinned in build.zig.zon, deps.yaml, CI and the README; `bun scripts/check-pin.ts`).
- `zig build test`, `zig build fuzz -Dfuzz-iterations=100000`, `zig build bench -Dbench`.
- Bounded memory: stream, never buffer a whole message; every depth, header size and line length
  has a limit, and running into one is reported, not silently truncated.
- Accept what real senders produce (bare LF, missing final boundary, duplicate boundaries) and
  document each tolerance with a test, because attackers use the gaps between parsers.
- Small conventional commits to `main`; no em-dashes or en-dashes in docs or messages.

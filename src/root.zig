//! zig-mime: a streaming MIME parser with bounded memory.
//!
//! Feed a message to a `Walker` in chunks of any size and receive events through a `Sink`:
//! `part_begin` with the parsed headers, `body` chunks, `part_end`, and `diagnostic` events for
//! every limit reached and every malformation tolerated. Nothing allocates; the caller provides
//! a scratch buffer for header blocks.
const std = @import("std");

pub const walker = @import("walker.zig");
pub const headers = @import("headers.zig");
pub const scan = @import("scan.zig");
pub const decode = @import("decode.zig");
pub const text = @import("text.zig");

pub const Walker = walker.Walker;
pub const Sink = walker.Sink;
pub const Event = walker.Event;
pub const Part = walker.Part;
pub const Kind = walker.Kind;
pub const Body = walker.Body;
pub const Region = walker.Region;
pub const PartEnd = walker.PartEnd;
pub const Diagnostic = walker.Diagnostic;
pub const DiagnosticKind = walker.DiagnosticKind;
pub const Options = walker.Options;
pub const Headers = headers.Headers;
pub const ContentType = headers.ContentType;
pub const Encoding = decode.Encoding;
pub const Disposition = headers.Disposition;
pub const validateBoundary = headers.validateBoundary;
pub const decodeWords = text.decodeWords;
pub const decodeParam = text.decodeParam;
pub const Transcript = @import("transcript.zig").Transcript;

pub const version = std.SemanticVersion{ .major = 0, .minor = 1, .patch = 0 };

test {
    std.testing.refAllDecls(@This());
    _ = @import("tests.zig");
}

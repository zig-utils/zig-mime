//! zig-mime: a streaming MIME parser. Nested multipart walking with bounded memory and streaming
//! transfer decoding land with issues P2.11 to P2.15.
const std = @import("std");

pub const version = std.SemanticVersion{ .major = 0, .minor = 0, .patch = 0 };

test {
    std.testing.refAllDecls(@This());
}

//! Streaming transfer decoding: one `Decoder` per part body, feeding decoded chunks to a sink.
const std = @import("std");

pub const base64 = @import("decode/base64.zig");
pub const qp = @import("decode/qp.zig");
pub const Flags = @import("decode/flags.zig").Flags;

/// The Content-Transfer-Encoding of a part.
pub const Encoding = enum {
    /// No Content-Transfer-Encoding field: 7bit by RFC 2045.
    none,
    seven_bit,
    eight_bit,
    binary,
    base64,
    quoted_printable,
    /// An encoding this library does not decode (such as x-uuencode); the body is passed on as
    /// it is.
    unknown,

    pub fn parse(value: []const u8) Encoding {
        const v = std.mem.trim(u8, value, " \t\r\n");
        const names = .{
            .{ "7bit", Encoding.seven_bit },
            .{ "8bit", Encoding.eight_bit },
            .{ "binary", Encoding.binary },
            .{ "base64", Encoding.base64 },
            .{ "quoted-printable", Encoding.quoted_printable },
        };
        inline for (names) |n| {
            if (std.ascii.eqlIgnoreCase(v, n[0])) return n[1];
        }
        return .unknown;
    }

    /// True when the body bytes are the content bytes.
    pub fn isIdentity(self: Encoding) bool {
        return self != .base64 and self != .quoted_printable;
    }
};

pub const Decoder = union(enum) {
    identity,
    base64: base64.Decoder,
    quoted_printable: qp.Decoder,

    /// Smallest staging buffer `feed` and `finish` accept.
    pub const min_buffer = 64;

    pub fn init(encoding: Encoding) Decoder {
        return switch (encoding) {
            .base64 => .{ .base64 = .{} },
            .quoted_printable => .{ .quoted_printable = .{} },
            else => .identity,
        };
    }

    /// Decodes `in` and calls `sink.write(bytes)` with each decoded chunk. Decoded bytes are
    /// staged in `buf` (at least `min_buffer` bytes); identity bodies are passed through
    /// without copying.
    pub fn feed(self: *Decoder, in: []const u8, buf: []u8, sink: anytype) !void {
        std.debug.assert(buf.len >= min_buffer);
        switch (self.*) {
            .identity => if (in.len > 0) try sink.write(in),
            inline .base64, .quoted_printable => |*d| {
                const D = @TypeOf(d.*);
                const step = D.maxInput(buf.len);
                var rest = in;
                while (rest.len > 0) {
                    const n = @min(step, rest.len);
                    const out = d.decode(rest[0..n], buf);
                    if (out > 0) try sink.write(buf[0..out]);
                    rest = rest[n..];
                }
            },
        }
    }

    /// Flushes what the decoder holds at the end of the body.
    pub fn finish(self: *Decoder, buf: []u8, sink: anytype) !void {
        switch (self.*) {
            .identity => {},
            inline .base64, .quoted_printable => |*d| {
                const out = d.finish(buf);
                if (out > 0) try sink.write(buf[0..out]);
            },
        }
    }

    pub fn flags(self: Decoder) Flags {
        return switch (self) {
            .identity => .{},
            inline .base64, .quoted_printable => |d| d.flags,
        };
    }
};

test "Encoding.parse" {
    try std.testing.expectEqual(Encoding.base64, Encoding.parse(" Base64\r\n"));
    try std.testing.expectEqual(Encoding.quoted_printable, Encoding.parse("Quoted-Printable"));
    try std.testing.expectEqual(Encoding.unknown, Encoding.parse("x-uuencode"));
}

test "Decoder feeds a sink chunk by chunk" {
    const Collect = struct {
        buf: [256]u8 = undefined,
        len: usize = 0,
        pub fn write(self: *@This(), bytes: []const u8) !void {
            @memcpy(self.buf[self.len..][0..bytes.len], bytes);
            self.len += bytes.len;
        }
    };
    var c: Collect = .{};
    var d = Decoder.init(.base64);
    var buf: [64]u8 = undefined;
    const text = "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4gVGhlIHF1aWNrIGJyb3du\r\nIGZveA==";
    try d.feed(text[0..50], &buf, &c);
    try d.feed(text[50..], &buf, &c);
    try d.finish(&buf, &c);
    try std.testing.expectEqualStrings("The quick brown fox jumps over the lazy dog. The quick brown fox", c.buf[0..c.len]);
}

test {
    _ = base64;
    _ = qp;
}

//! Streaming base64 decoder (RFC 2045 section 6.8) that tolerates what real senders produce.
//!
//! Line breaks and whitespace are skipped. Characters outside the alphabet are skipped and set
//! `Flags.invalid_input`. Padding ends a quantum, and decoding resumes after it: concatenated
//! base64 bodies decode completely, which is the view a scanner needs, and set
//! `Flags.padding_inside`. Partial quanta are carried across calls, so any split of the input
//! gives the same output. The fast path converts 16 input characters to 12 bytes with vector
//! operations whenever no whitespace or padding is in the way.
const std = @import("std");
const builtin = @import("builtin");
const Flags = @import("flags.zig").Flags;

const invalid: u8 = 0xff;
const space: u8 = 0xfe;
const pad: u8 = 0xfd;

const table: [256]u8 = blk: {
    var t: [256]u8 = @splat(invalid);
    for ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", 0..) |c, i| t[c] = i;
    for (" \t\r\n") |c| t[c] = space;
    t['='] = pad;
    break :blk t;
};

pub const Decoder = struct {
    acc: u32 = 0,
    /// Sextets held in `acc` (0 to 3).
    held: u8 = 0,
    after_pad: bool = false,
    flags: Flags = .{},

    /// Output space `decode` needs for `in_len` input bytes.
    pub fn maxOutput(in_len: usize) usize {
        return (in_len + 3) / 4 * 3;
    }

    /// Largest input `decode` accepts with `out_len` bytes of output space.
    pub fn maxInput(out_len: usize) usize {
        return out_len / 3 * 4 - 3;
    }

    /// Decodes `in` into `out` (at least `maxOutput(in.len)` bytes) and returns the bytes written.
    pub fn decode(self: *Decoder, in: []const u8, out: []u8) usize {
        std.debug.assert(out.len >= maxOutput(in.len));
        var i: usize = 0;
        var w: usize = 0;
        while (i < in.len) {
            if (use_simd and self.held == 0 and !self.after_pad) {
                while (i + 16 <= in.len) {
                    if (!decode16(in[i..][0..16], out[w..][0..12])) break;
                    i += 16;
                    w += 12;
                }
            }
            // Whole quanta of alphabet characters, four table lookups and no state.
            if (self.held == 0 and !self.after_pad) {
                while (i + 4 <= in.len) {
                    const a = table[in[i]];
                    const b = table[in[i + 1]];
                    const c = table[in[i + 2]];
                    const d = table[in[i + 3]];
                    if ((a | b | c | d) >= 64) break;
                    const v = (@as(u32, a) << 18) | (@as(u32, b) << 12) | (@as(u32, c) << 6) | d;
                    out[w] = @truncate(v >> 16);
                    out[w + 1] = @truncate(v >> 8);
                    out[w + 2] = @truncate(v);
                    w += 3;
                    i += 4;
                }
            }
            // Scalar until the next line break, where the vector path can usually resume.
            while (i < in.len) {
                const c = in[i];
                i += 1;
                const v = table[c];
                if (v < 64) {
                    if (self.after_pad) {
                        self.after_pad = false;
                        self.flags.padding_inside = true;
                    }
                    self.acc = (self.acc << 6) | v;
                    self.held += 1;
                    if (self.held == 4) {
                        out[w] = @truncate(self.acc >> 16);
                        out[w + 1] = @truncate(self.acc >> 8);
                        out[w + 2] = @truncate(self.acc);
                        w += 3;
                        self.acc = 0;
                        self.held = 0;
                    }
                } else if (v == space) {
                    if (c == '\n') break;
                } else if (v == pad) {
                    w += self.endQuantum(out[w..]);
                    self.after_pad = true;
                } else {
                    self.flags.invalid_input = true;
                }
            }
        }
        return w;
    }

    /// Flushes a partial final quantum (at most 2 bytes) at the end of the body.
    pub fn finish(self: *Decoder, out: []u8) usize {
        if (self.held > 0) self.flags.truncated = true;
        return self.endQuantum(out);
    }

    fn endQuantum(self: *Decoder, out: []u8) usize {
        defer {
            self.acc = 0;
            self.held = 0;
        }
        switch (self.held) {
            0 => return 0,
            1 => {
                // Six bits cannot form a byte.
                self.flags.invalid_input = true;
                return 0;
            },
            2 => {
                out[0] = @truncate(self.acc >> 4);
                return 1;
            },
            3 => {
                out[0] = @truncate(self.acc >> 10);
                out[1] = @truncate(self.acc >> 2);
                return 2;
            },
            else => unreachable,
        }
    }
};

const use_simd = builtin.cpu.arch.endian() == .little;

const V16 = @Vector(16, u8);

/// Decodes 16 alphabet characters into 12 bytes; false (and nothing written) if any of them is
/// not in the alphabet.
fn decode16(in: *const [16]u8, out: *[12]u8) bool {
    const c: V16 = in.*;
    const upper = (c >= @as(V16, @splat('A'))) & (c <= @as(V16, @splat('Z')));
    const lower = (c >= @as(V16, @splat('a'))) & (c <= @as(V16, @splat('z')));
    const digit = (c >= @as(V16, @splat('0'))) & (c <= @as(V16, @splat('9')));
    const plus = c == @as(V16, @splat('+'));
    const slash = c == @as(V16, @splat('/'));
    const valid = upper | lower | digit | plus | slash;
    if (!@reduce(.And, valid)) return false;
    var s: V16 = @select(u8, upper, c -% @as(V16, @splat('A')), @as(V16, @splat(0)));
    s = @select(u8, lower, c -% @as(V16, @splat('a' - 26)), s);
    s = @select(u8, digit, c +% @as(V16, @splat(52 - '0')), s);
    s = @select(u8, plus, @as(V16, @splat(62)), s);
    s = @select(u8, slash, @as(V16, @splat(63)), s);
    // Each little-endian u32 lane holds four sextets a, b, c, d in its bytes.
    const x: @Vector(4, u32) = @bitCast(s);
    const m: @Vector(4, u32) = @splat(0xff);
    const v = ((x & m) << @splat(18)) | (((x >> @splat(8)) & m) << @splat(12)) |
        (((x >> @splat(16)) & m) << @splat(6)) | (x >> @splat(24));
    const bytes: V16 = @bitCast(@byteSwap(v));
    out.* = @shuffle(u8, bytes, undefined, [12]i32{ 1, 2, 3, 5, 6, 7, 9, 10, 11, 13, 14, 15 });
    return true;
}

const testing = std.testing;

fn decodeAll(in: []const u8, cuts: []const usize, out: []u8) struct { len: usize, flags: Flags } {
    var d: Decoder = .{};
    var w: usize = 0;
    var prev: usize = 0;
    for (cuts) |c| {
        w += d.decode(in[prev..c], out[w..]);
        prev = c;
    }
    w += d.decode(in[prev..], out[w..]);
    w += d.finish(out[w..]);
    return .{ .len = w, .flags = d.flags };
}

const Vector = struct { in: []const u8, out: []const u8, flags: Flags = .{} };

const vectors = [_]Vector{
    // RFC 4648 section 10.
    .{ .in = "", .out = "" },
    .{ .in = "Zg==", .out = "f" },
    .{ .in = "Zm8=", .out = "fo" },
    .{ .in = "Zm9v", .out = "foo" },
    .{ .in = "Zm9vYg==", .out = "foob" },
    .{ .in = "Zm9vYmE=", .out = "fooba" },
    .{ .in = "Zm9vYmFy", .out = "foobar" },
    // MIME line wrapping, bare LF, spaces.
    .{ .in = "TWFu\r\nIGlz\r\nIGRp\nc3Rp bmd1\taXNo\r\nZWQ=\r\n", .out = "Man is distinguished" },
    // Long lines take the vector path.
    .{
        .in = "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4gVGhlIHF1aWNrIGJyb3du\r\nIGZveA==\r\n",
        .out = "The quick brown fox jumps over the lazy dog. The quick brown fox",
    },
    // Garbage is skipped and flagged.
    .{ .in = "Zm9v!YmFy", .out = "foobar", .flags = .{ .invalid_input = true } },
    // Concatenated bodies decode past the padding.
    .{ .in = "Zm8=YmFy", .out = "fobar", .flags = .{ .padding_inside = true } },
    // Missing padding is tolerated at the end, a lone sextet is not.
    .{ .in = "Zm9vYg", .out = "foob", .flags = .{ .truncated = true } },
    .{ .in = "Zm9vY", .out = "foo", .flags = .{ .truncated = true, .invalid_input = true } },
};

test "base64 vectors decode identically under every split" {
    var out: [256]u8 = undefined;
    for (vectors) |v| {
        const whole = decodeAll(v.in, &.{}, &out);
        try testing.expectEqualStrings(v.out, out[0..whole.len]);
        try testing.expectEqual(v.flags, whole.flags);
        for (0..v.in.len + 1) |a| {
            for (a..v.in.len + 1) |b| {
                const got = decodeAll(v.in, &.{ a, b }, &out);
                try testing.expectEqualStrings(v.out, out[0..got.len]);
                try testing.expectEqual(v.flags, got.flags);
            }
        }
    }
}

test "base64 matches std on random data and random splits" {
    var prng = std.Random.DefaultPrng.init(0xb64);
    const random = prng.random();
    var raw: [600]u8 = undefined;
    var enc: [1000]u8 = undefined;
    var wrapped: [1100]u8 = undefined;
    var out: [1100]u8 = undefined;
    for (0..500) |_| {
        const n = random.uintLessThan(usize, raw.len);
        random.bytes(raw[0..n]);
        const e = std.base64.standard.Encoder.encode(&enc, raw[0..n]);
        var wl: usize = 0;
        for (e, 0..) |c, i| {
            if (i > 0 and i % 76 == 0) {
                wrapped[wl] = '\r';
                wrapped[wl + 1] = '\n';
                wl += 2;
            }
            wrapped[wl] = c;
            wl += 1;
        }
        var cuts: [4]usize = undefined;
        for (&cuts) |*c| c.* = random.uintAtMost(usize, wl);
        std.mem.sort(usize, &cuts, {}, std.sort.asc(usize));
        const got = decodeAll(wrapped[0..wl], &cuts, &out);
        try testing.expectEqualSlices(u8, raw[0..n], out[0..got.len]);
        try testing.expectEqual(Flags{}, got.flags);
    }
}

test "base64 never exceeds its output bound on arbitrary input" {
    var prng = std.Random.DefaultPrng.init(0xbad);
    const random = prng.random();
    var in: [300]u8 = undefined;
    var out: [300]u8 = undefined;
    var ref: [300]u8 = undefined;
    for (0..2000) |_| {
        const n = random.uintLessThan(usize, in.len);
        for (in[0..n]) |*c| c.* = if (random.boolean()) "AZaz09+/=\r\n "[random.uintLessThan(usize, 12)] else random.int(u8);
        const whole = decodeAll(in[0..n], &.{}, &ref);
        const cut = random.uintAtMost(usize, n);
        const split = decodeAll(in[0..n], &.{cut}, &out);
        try testing.expectEqualSlices(u8, ref[0..whole.len], out[0..split.len]);
        try testing.expectEqual(whole.flags, split.flags);
        try testing.expect(whole.len <= Decoder.maxOutput(n));
        try testing.expect(Decoder.maxOutput(Decoder.maxInput(n + 64)) <= n + 64);
    }
}

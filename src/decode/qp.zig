//! Streaming quoted-printable decoder (RFC 2045 section 6.7).
//!
//! `=XX` escapes (either hex case) become bytes, and `=` before a line break is a soft break that
//! disappears, also when transport padding (spaces or tabs) sits between them. Malformed escapes
//! are kept literally and set `Flags.invalid_input`, the way mail clients show them. A partial
//! escape is carried across calls, so any split of the input gives the same output. Runs of
//! plain text are copied in bulk between '=' signs.
const std = @import("std");
const Flags = @import("flags.zig").Flags;

/// Transport padding held after '=' while waiting to see whether a line break follows.
const ws_cap = 16;

pub const Decoder = struct {
    state: enum { text, eq, hex, eq_cr, eq_ws } = .text,
    hex1: u8 = 0,
    ws: [ws_cap]u8 = undefined,
    ws_len: u8 = 0,
    flags: Flags = .{},

    /// Output space `decode` needs for `in_len` input bytes: a held escape and its padding can
    /// come out literally on top of the input.
    pub fn maxOutput(in_len: usize) usize {
        return in_len + 2 + ws_cap;
    }

    /// Largest input `decode` accepts with `out_len` bytes of output space.
    pub fn maxInput(out_len: usize) usize {
        return out_len - 2 - ws_cap;
    }

    /// Decodes `in` into `out` (at least `maxOutput(in.len)` bytes) and returns the bytes written.
    pub fn decode(self: *Decoder, in: []const u8, out: []u8) usize {
        std.debug.assert(out.len >= maxOutput(in.len));
        var i: usize = 0;
        var w: usize = 0;
        while (i < in.len) {
            switch (self.state) {
                .text => {
                    const end = std.mem.indexOfScalarPos(u8, in, i, '=') orelse in.len;
                    @memcpy(out[w..][0 .. end - i], in[i..end]);
                    w += end - i;
                    i = end;
                    if (i == in.len) break;
                    // A complete escape inside this chunk decodes without a state change.
                    if (i + 2 < in.len) {
                        if (hexValue(in[i + 1])) |hi| {
                            if (hexValue(in[i + 2])) |lo| {
                                out[w] = (hi << 4) | lo;
                                w += 1;
                                i += 3;
                                continue;
                            }
                        }
                    }
                    self.state = .eq;
                    i += 1;
                },
                .eq => {
                    const c = in[i];
                    i += 1;
                    if (hexValue(c) != null) {
                        self.hex1 = c;
                        self.state = .hex;
                    } else switch (c) {
                        '\n' => self.state = .text,
                        '\r' => self.state = .eq_cr,
                        ' ', '\t' => {
                            self.ws[0] = c;
                            self.ws_len = 1;
                            self.state = .eq_ws;
                        },
                        else => {
                            w += self.literal(out[w..], "=");
                            i -= 1; // decode c as text, it may start another escape
                        },
                    }
                },
                .hex => {
                    const c = in[i];
                    if (hexValue(c)) |lo| {
                        out[w] = (hexValue(self.hex1).? << 4) | lo;
                        w += 1;
                        i += 1;
                        self.state = .text;
                    } else {
                        w += self.literal(out[w..], &.{ '=', self.hex1 });
                    }
                },
                .eq_cr => {
                    if (in[i] == '\n') {
                        i += 1;
                        self.state = .text;
                    } else {
                        w += self.literal(out[w..], "=\r");
                    }
                },
                .eq_ws => {
                    const c = in[i];
                    switch (c) {
                        ' ', '\t' => {
                            if (self.ws_len == ws_cap) {
                                w += self.literalWs(out[w..]);
                            } else {
                                self.ws[self.ws_len] = c;
                                self.ws_len += 1;
                                i += 1;
                            }
                        },
                        '\n' => {
                            i += 1;
                            self.state = .text;
                        },
                        '\r' => {
                            i += 1;
                            self.state = .eq_cr;
                        },
                        else => w += self.literalWs(out[w..]),
                    }
                },
            }
        }
        return w;
    }

    /// Ends the body. A final '=' (with or without padding or a CR) is a soft break; half an
    /// escape comes out literally.
    pub fn finish(self: *Decoder, out: []u8) usize {
        defer self.state = .text;
        return switch (self.state) {
            .text, .eq, .eq_cr, .eq_ws => 0,
            .hex => self.literal(out, &.{ '=', self.hex1 }),
        };
    }

    /// Emits held bytes that turned out not to be an escape and returns to text.
    fn literal(self: *Decoder, out: []u8, bytes: []const u8) usize {
        self.flags.invalid_input = true;
        self.state = .text;
        @memcpy(out[0..bytes.len], bytes);
        return bytes.len;
    }

    fn literalWs(self: *Decoder, out: []u8) usize {
        const n = self.ws_len;
        out[0] = '=';
        @memcpy(out[1..][0..n], self.ws[0..n]);
        self.ws_len = 0;
        self.flags.invalid_input = true;
        self.state = .text;
        return n + 1;
    }
};

fn hexValue(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'A'...'F' => c - 'A' + 10,
        'a'...'f' => c - 'a' + 10,
        else => null,
    };
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
    .{ .in = "", .out = "" },
    .{ .in = "plain text\r\n", .out = "plain text\r\n" },
    .{ .in = "caf=C3=A9 =3d =3D", .out = "caf\xc3\xa9 = =" },
    .{ .in = "soft=\r\nbreak", .out = "softbreak" },
    .{ .in = "soft=\nbreak", .out = "softbreak" },
    .{ .in = "padded=  \t\r\nbreak", .out = "paddedbreak" },
    .{ .in = "trailing=", .out = "trailing" },
    .{ .in = "bad=ZZ", .out = "bad=ZZ", .flags = .{ .invalid_input = true } },
    .{ .in = "half=4", .out = "half=4", .flags = .{ .invalid_input = true } },
    .{ .in = "half=4x", .out = "half=4x", .flags = .{ .invalid_input = true } },
    .{ .in = "==41", .out = "=A", .flags = .{ .invalid_input = true } },
    .{ .in = "=\rx", .out = "=\rx", .flags = .{ .invalid_input = true } },
    .{ .in = "= x", .out = "= x", .flags = .{ .invalid_input = true } },
};

test "quoted-printable vectors decode identically under every split" {
    var out: [128]u8 = undefined;
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

test "quoted-printable padding longer than the hold buffer comes out literally" {
    var in: [40]u8 = undefined;
    in[0] = '=';
    @memset(in[1..30], ' ');
    @memcpy(in[30..32], "\r\n");
    var out: [128]u8 = undefined;
    const r = decodeAll(in[0..32], &.{}, &out);
    try testing.expect(r.flags.invalid_input);
    try testing.expectEqualStrings(in[0..32], out[0..r.len]);
}

test "quoted-printable never exceeds its output bound and is split invariant" {
    var prng = std.Random.DefaultPrng.init(0x9b);
    const random = prng.random();
    var in: [200]u8 = undefined;
    var out: [300]u8 = undefined;
    var ref: [300]u8 = undefined;
    for (0..3000) |_| {
        const n = random.uintLessThan(usize, in.len);
        for (in[0..n]) |*c| c.* = "=0aF \t\r\nx"[random.uintLessThan(usize, 9)];
        const whole = decodeAll(in[0..n], &.{}, &ref);
        try testing.expect(whole.len <= Decoder.maxOutput(n));
        const a = random.uintAtMost(usize, n);
        const b = random.uintAtMost(usize, n);
        const split = decodeAll(in[0..n], &.{ @min(a, b), @max(a, b) }, &out);
        try testing.expectEqualSlices(u8, ref[0..whole.len], out[0..split.len]);
        try testing.expectEqual(whole.flags, split.flags);
    }
}

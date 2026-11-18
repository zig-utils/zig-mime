//! Deterministic fuzzing: `zig build fuzz -Dfuzz-iterations=N -Dfuzz-seed=S [-Dfuzz-seconds=T]`.
//!
//! Targets:
//! - walker: generated and mutated messages, walked whole and in random chunks. The transcripts
//!   must match, the event stream must nest, and scratch use must stay within the buffer.
//! - headers: random parameter lists and header text through ContentType, the parameter
//!   iterator, RFC 2047 and RFC 2231 decoding into small buffers, and unfolding (idempotent).
//! - decoders: random input through base64 and quoted-printable under random splits.
//!
//! The walker, headers and decoders never get an allocator; only the transcripts used to
//! compare runs allocate.
const std = @import("std");
const mime = @import("mime");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const iterations = if (args.len > 1) try std.fmt.parseInt(usize, args[1], 10) else 10_000;
    const seed = if (args.len > 2) try std.fmt.parseInt(u64, args[2], 10) else 0x5eed_5eed;
    const seconds = if (args.len > 3) try std.fmt.parseInt(u64, args[3], 10) else 0;
    const io = init.io;
    const gpa = init.gpa;

    const start = std.Io.Clock.awake.now(io);
    var case: usize = 0;
    var bytes: u64 = 0;
    while (true) : (case += 1) {
        if (seconds == 0) {
            if (case >= iterations) break;
        } else if (case % 256 == 0) {
            const elapsed = start.durationTo(std.Io.Clock.awake.now(io)).nanoseconds;
            if (elapsed >= @as(i96, seconds) * std.time.ns_per_s) break;
        }
        var prng = std.Random.DefaultPrng.init(seed +% case *% 0x9e3779b97f4a7c15);
        const r = prng.random();
        bytes += switch (case % 4) {
            0, 1 => try fuzzWalker(gpa, r, case),
            2 => try fuzzHeaders(r, case),
            else => try fuzzDecoders(r, case),
        };
    }
    std.debug.print("fuzz: {d} cases ({d} KiB of input), seed {d}, no findings\n", .{ case, bytes / 1024, seed });
}

// Walker

const boundaries = [_][]const u8{ "a", "b", "x1", "=_p", "----=_Part_1", "a b", "q\"z", "--", "-" };

const Gen = struct {
    r: std.Random,
    out: std.ArrayList(u8) = .empty,
    gpa: std.mem.Allocator,
    mode: enum { crlf, lf, mixed },

    fn put(self: *Gen, s: []const u8) !void {
        try self.out.appendSlice(self.gpa, s);
    }

    fn eol(self: *Gen) !void {
        const crlf = switch (self.mode) {
            .crlf => true,
            .lf => false,
            .mixed => self.r.boolean(),
        };
        try self.put(if (crlf) "\r\n" else "\n");
    }

    fn pick(self: *Gen, comptime T: type, items: []const T) T {
        return items[self.r.uintLessThan(usize, items.len)];
    }

    fn entity(self: *Gen, depth: usize) !void {
        const r = self.r;
        const multipart = depth < 5 and r.uintLessThan(u8, 3) == 0;
        const message = !multipart and depth < 5 and r.uintLessThan(u8, 12) == 0;
        const boundary = self.pick([]const u8, &boundaries);
        const encoding = self.pick([]const u8, &.{ "base64", "quoted-printable", "7bit", "x-uuencode", "BASE64" });
        const encoded = !multipart and !message and r.boolean();

        const nfields = r.uintLessThan(usize, 6);
        for (0..nfields + 1) |i| {
            if (i == nfields or r.uintLessThan(u8, 4) == 0) {
                if (multipart) {
                    try self.put("Content-Type: multipart/");
                    try self.put(self.pick([]const u8, &.{ "mixed", "alternative", "digest", "related" }));
                    try self.put("; boundary=\"");
                    try self.put(boundary);
                    try self.put("\"");
                    if (r.uintLessThan(u8, 6) == 0) {
                        try self.put("; boundary=");
                        try self.put(self.pick([]const u8, &boundaries));
                    }
                } else if (message) {
                    try self.put("Content-Type: message/rfc822");
                } else {
                    try self.put(self.pick([]const u8, &.{
                        "Content-Type: text/plain; charset=utf-8",
                        "Content-Type: application/octet-stream; name=\"=?UTF-8?B?Y2Fmw6kucGRm?=\"",
                        "Content-Type: text",
                        "Content-Type: image/png; name*0*=utf-8''a%20b; name*1=\".png\"",
                    }));
                }
                try self.eol();
                if (i == nfields) break;
            }
            switch (r.uintLessThan(u8, 9)) {
                0 => {
                    try self.put("Content-Transfer-Encoding: ");
                    try self.put(if (encoded) encoding else "8bit");
                },
                1 => try self.put("Content-Disposition: attachment; filename=\"x.exe\"; filename*=utf-8''y%2Eexe"),
                2 => try self.put("Subject: =?iso-8859-1?q?caf=E9?= =?utf-8?b?w6k=?="),
                3 => {
                    try self.put("X-Folded: one");
                    try self.eol();
                    try self.put("\ttwo");
                },
                4 => for (0..r.uintLessThan(usize, 300)) |_| try self.put("x"),
                5 => try self.put("not a header line"),
                6 => try self.put(" orphan continuation"),
                else => try self.put("X-Junk: value"),
            }
            try self.eol();
            if (encoded and i == 0) {
                try self.put("Content-Transfer-Encoding: ");
                try self.put(encoding);
                try self.eol();
            }
        }
        if (r.uintLessThan(u8, 16) != 0) try self.eol();

        if (multipart) {
            if (r.boolean()) {
                try self.put("preamble");
                try self.eol();
            }
            const children = r.uintLessThan(usize, 4);
            for (0..children) |_| {
                try self.put("--");
                try self.put(boundary);
                if (r.uintLessThan(u8, 10) == 0) try self.put("garbage");
                try self.eol();
                try self.entity(depth + 1);
                try self.eol();
            }
            if (r.uintLessThan(u8, 5) != 0) {
                try self.put("--");
                try self.put(boundary);
                try self.put("--");
                try self.eol();
            }
            if (r.boolean()) try self.put("epilogue");
        } else if (message) {
            try self.entity(depth + 1);
        } else {
            try self.leafBody(encoded, encoding);
        }
    }

    fn leafBody(self: *Gen, encoded: bool, encoding: []const u8) !void {
        const r = self.r;
        var raw: [600]u8 = undefined;
        const n = r.uintLessThan(usize, raw.len);
        r.bytes(raw[0..n]);
        if (encoded and std.ascii.eqlIgnoreCase(encoding, "base64")) {
            var enc: [800]u8 = undefined;
            const e = std.base64.standard.Encoder.encode(&enc, raw[0..n]);
            var i: usize = 0;
            while (i < e.len) : (i += 76) {
                try self.put(e[i..@min(i + 76, e.len)]);
                try self.eol();
            }
        } else if (encoded) {
            for (raw[0..n], 0..) |c, i| {
                if (c >= 33 and c <= 126 and c != '=') {
                    try self.out.append(self.gpa, c);
                } else {
                    try self.out.print(self.gpa, "={X:0>2}", .{c});
                }
                if (i % 60 == 59) {
                    try self.put("=");
                    try self.eol();
                }
            }
        } else {
            // Text with lines that resemble delimiters.
            for (0..r.uintLessThan(usize, 8)) |_| {
                switch (r.uintLessThan(u8, 6)) {
                    0 => {
                        try self.put("--");
                        try self.put(self.pick([]const u8, &boundaries)[0..1]);
                    },
                    1 => try self.put("-- "),
                    2 => try self.put(raw[0..@min(n, 40)]),
                    else => try self.put("plain text line"),
                }
                try self.eol();
            }
        }
    }
};

fn mutate(r: std.Random, gpa: std.mem.Allocator, buf: *std.ArrayList(u8)) !void {
    const n = r.uintLessThan(usize, 5);
    for (0..n) |_| {
        if (buf.items.len == 0) return;
        const at = r.uintLessThan(usize, buf.items.len);
        switch (r.uintLessThan(u8, 5)) {
            0 => buf.items[at] = r.int(u8),
            1 => _ = buf.orderedRemove(at),
            2 => try buf.insertSlice(gpa, at, "\r\n--"),
            3 => try buf.insertSlice(gpa, at, boundaries[r.uintLessThan(usize, boundaries.len)]),
            else => {
                const len = @min(r.uintLessThan(usize, 64), buf.items.len - at);
                const copy = try gpa.dupe(u8, buf.items[at..][0..len]);
                defer gpa.free(copy);
                try buf.insertSlice(gpa, at, copy);
            },
        }
    }
}

/// Checks that events nest and wraps a transcript.
const Checker = struct {
    transcript: mime.Transcript,
    stack: [64]u32 = undefined,
    len: usize = 0,
    bad: ?[]const u8 = null,

    pub fn onEvent(self: *Checker, event: mime.Event) mime.Sink.Error!void {
        switch (event) {
            .part_begin => |p| {
                if (p.depth != self.len) self.bad = "part_begin depth does not match nesting";
                if (self.len == self.stack.len) {
                    self.bad = "nesting too deep";
                    return error.Aborted;
                }
                self.stack[self.len] = p.index;
                self.len += 1;
            },
            .body => |b| {
                if (self.len == 0 or self.stack[self.len - 1] != b.part.index) self.bad = "body for a part that is not innermost";
                if (b.bytes.len == 0) self.bad = "empty body event";
            },
            .part_end => |e| {
                if (self.len == 0 or self.stack[self.len - 1] != e.part.index) {
                    self.bad = "part_end out of order";
                } else self.len -= 1;
            },
            .diagnostic => {},
        }
        try self.transcript.onEvent(event);
    }
};

const Run = struct { text: []u8, peak: usize };

fn walkOnce(gpa: std.mem.Allocator, data: []const u8, cuts: []const usize, scratch: []u8, options: mime.Options, case: usize) !Run {
    var checker: Checker = .{ .transcript = .init(gpa) };
    defer checker.transcript.deinit();
    var w = mime.Walker.init(scratch, mime.Sink.init(&checker), options);
    var prev: usize = 0;
    for (cuts) |c| {
        try w.feed(data[prev..c]);
        prev = c;
    }
    try w.feed(data[prev..]);
    try w.finish();
    if (checker.bad) |why| {
        std.debug.print("options {any}, scratch {d}\n--- transcript\n{s}---\n", .{ options, scratch.len, checker.transcript.text() });
        return finding(case, why, data);
    }
    if (checker.len != 0) return finding(case, "parts left open after finish", data);
    return .{ .text = try gpa.dupe(u8, checker.transcript.text()), .peak = w.scratch_peak };
}

fn fuzzWalker(gpa: std.mem.Allocator, r: std.Random, case: usize) !u64 {
    var gen: Gen = .{ .r = r, .gpa = gpa, .mode = switch (r.uintLessThan(u8, 3)) {
        0 => .crlf,
        1 => .lf,
        else => .mixed,
    } };
    defer gen.out.deinit(gpa);
    try gen.entity(0);
    if (r.boolean()) try mutate(r, gpa, &gen.out);
    const data = gen.out.items;

    const scratch_sizes = [_]usize{ 64, 300, 4096 };
    const scratch_len = scratch_sizes[r.uintLessThan(usize, scratch_sizes.len)];
    const scratch = try gpa.alloc(u8, scratch_len);
    defer gpa.free(scratch);
    const options: mime.Options = .{
        .max_depth = r.intRangeAtMost(u8, 1, 16),
        .max_parts = r.intRangeAtMost(u32, 1, 40),
        .max_header_bytes = r.intRangeAtMost(u32, 16, 2048),
        .raw_view = r.boolean(),
    };

    const whole = try walkOnce(gpa, data, &.{}, scratch, options, case);
    defer gpa.free(whole.text);
    if (whole.peak > scratch.len) return finding(case, "scratch use beyond the buffer", data);

    var cuts: [6]usize = undefined;
    const ncuts = r.uintAtMost(usize, cuts.len);
    for (cuts[0..ncuts]) |*c| c.* = r.uintAtMost(usize, data.len);
    std.mem.sort(usize, cuts[0..ncuts], {}, std.sort.asc(usize));
    const split = try walkOnce(gpa, data, cuts[0..ncuts], scratch, options, case);
    defer gpa.free(split.text);
    if (!std.mem.eql(u8, whole.text, split.text)) return mismatch(case, "chunking changed the event stream", data, options, scratch_len, whole.text, split.text);

    if (data.len < 2048 and r.uintLessThan(u8, 8) == 0) {
        const all = try gpa.alloc(usize, data.len);
        defer gpa.free(all);
        for (all, 0..) |*c, i| c.* = i;
        const bytewise = try walkOnce(gpa, data, all, scratch, options, case);
        defer gpa.free(bytewise.text);
        if (!std.mem.eql(u8, whole.text, bytewise.text)) return mismatch(case, "byte-at-a-time feeding changed the event stream", data, options, scratch_len, whole.text, bytewise.text);
    }
    return data.len;
}

// Headers

fn fuzzHeaders(r: std.Random, case: usize) !u64 {
    const pieces = [_][]const u8{
        "filename",   "*",          "0",               "1",      "*0*", "=",  ";",   "\"",    "\\",       "(",
        ")",          " ",          "\t",              "'",      "%",   "%2", "%41", "utf-8", "=E9",      "_",
        "Y2Fm",       "iso-8859-1", "windows-1252",    "koi8-r", "=?",  "?=", "?B?", "?Q?",   "boundary", "name",
        "text/plain", "\xff",       "multipart/mixed", "\r\n",   "a",
    };
    var in: [256]u8 = undefined;
    var n: usize = 0;
    while (n < in.len - 16 and r.uintLessThan(u8, 40) != 0) {
        const p = pieces[r.uintLessThan(usize, pieces.len)];
        @memcpy(in[n..][0..p.len], p);
        n += p.len;
    }
    const value = in[0..n];

    var out_buf: [96]u8 = undefined;
    const out = out_buf[0..r.uintAtMost(usize, out_buf.len)];
    if (mime.ContentType.parse(value)) |ct| {
        var it = ct.paramIterator();
        var count: usize = 0;
        while (it.next()) |p| : (count += 1) {
            if (p.name.len == 0) return finding(case, "empty parameter name", value);
            if (count > value.len) return finding(case, "parameter iterator does not terminate", value);
        }
    } else |_| {}
    inline for (.{ "filename", "name", "boundary" }) |name| {
        if (mime.text.decodeParam(value, name, out)) |res| try checkWithin(res.text, out, value, case);
        if (mime.text.decodeExtendedParam(value, name, out)) |res| try checkWithin(res.text, out, value, case);
    }
    try checkWithin(mime.text.decodeWords(value, out).text, out, value, case);

    var block: [256]u8 = undefined;
    @memcpy(block[0..n], value);
    const once = mime.headers.unfold(block[0..n]);
    var again_buf: [256]u8 = undefined;
    @memcpy(again_buf[0..once.len], once);
    const again = mime.headers.unfold(again_buf[0..once.len]);
    if (!std.mem.eql(u8, once, again)) return finding(case, "unfold is not idempotent", value);
    return n;
}

fn checkWithin(result: []const u8, out: []const u8, input: []const u8, case: usize) !void {
    const start = @intFromPtr(out.ptr);
    const ok = result.len <= out.len and (result.len == 0 or
        (@intFromPtr(result.ptr) >= start and @intFromPtr(result.ptr) + result.len <= start + out.len));
    if (!ok) return finding(case, "decoded text escaped its buffer", input);
}

// Decoders

fn fuzzDecoders(r: std.Random, case: usize) !u64 {
    var in: [512]u8 = undefined;
    const n = r.uintLessThan(usize, in.len);
    const alphabet = "AZaz09+/= \r\n\t!=3D=\r\n";
    for (in[0..n]) |*c| c.* = if (r.uintLessThan(u8, 4) == 0) r.int(u8) else alphabet[r.uintLessThan(usize, alphabet.len)];
    var a: [600]u8 = undefined;
    var b: [600]u8 = undefined;
    inline for (.{ mime.decode.base64.Decoder, mime.decode.qp.Decoder }) |D| {
        var d1: D = .{};
        var la = d1.decode(in[0..n], &a);
        if (la > D.maxOutput(n)) return finding(case, "decoder exceeded maxOutput", in[0..n]);
        la += d1.finish(a[la..]);
        var d2: D = .{};
        var lb: usize = 0;
        var prev: usize = 0;
        for (0..r.uintLessThan(usize, 5)) |_| {
            const cut = r.intRangeAtMost(usize, prev, n);
            lb += d2.decode(in[prev..cut], b[lb..]);
            prev = cut;
        }
        lb += d2.decode(in[prev..n], b[lb..]);
        lb += d2.finish(b[lb..]);
        if (!std.mem.eql(u8, a[0..la], b[0..lb]) or d1.flags != d2.flags) {
            return finding(case, "decoder output depends on the split", in[0..n]);
        }
    }
    return n;
}

fn mismatch(case: usize, why: []const u8, input: []const u8, options: mime.Options, scratch_len: usize, a: []const u8, b: []const u8) error{Finding} {
    std.debug.print("options {any}, scratch {d}\n--- whole\n{s}--- chunked\n{s}---\n", .{ options, scratch_len, a, b });
    return finding(case, why, input);
}

fn finding(case: usize, why: []const u8, input: []const u8) error{Finding} {
    std.debug.print("FINDING in case {d}: {s}\ninput ({d} bytes): {any}\n", .{ case, why, input.len, input });
    return error.Finding;
}

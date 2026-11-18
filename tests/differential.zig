//! Differential tests against the mail server's parser (tests/mail_reference.zig).
//!
//! 1. Well-formed messages, generated from a seed, must parse the same: the same top-level
//!    parts with the same media types and the same raw bodies, and the same Content-Type
//!    fields (type, subtype, boundary, charset).
//! 2. The evasion corpus is parsed by both, and whether they agree is pinned per sample. Every
//!    disagreement is intentional; the reason is written next to the sample. A change in either
//!    parser that flips an entry fails the test, so differences never appear unnoticed.
//!
//! The mail parser's own trimming is applied to both sides: it drops every trailing CR and LF
//! of a part body, where zig-mime drops only the line break that belongs to the delimiter.
const std = @import("std");
const mime = @import("mime");
const mail = @import("mail_reference");

const testing = std.testing;

const Part = struct {
    media_type: []const u8,
    media_subtype: []const u8,
    /// Raw body, trailing CR and LF trimmed; null for a nested multipart (mail gives its raw
    /// body, zig-mime walks it).
    body: ?[]const u8,
};

const Parts = struct {
    arena: std.heap.ArenaAllocator,
    list: std.ArrayList(Part) = .empty,

    fn init(gpa: std.mem.Allocator) Parts {
        return .{ .arena = .init(gpa) };
    }

    fn deinit(self: *Parts) void {
        self.arena.deinit();
    }

    fn dump(self: *const Parts, label: []const u8) void {
        std.debug.print("  {s}:\n", .{label});
        for (self.list.items) |p| std.debug.print("    {s}/{s} {?s}\n", .{ p.media_type, p.media_subtype, p.body });
    }

    fn eql(a: *const Parts, b: *const Parts) bool {
        if (a.list.items.len != b.list.items.len) return false;
        for (a.list.items, b.list.items) |x, y| {
            if (!std.ascii.eqlIgnoreCase(x.media_type, y.media_type)) return false;
            if (!std.ascii.eqlIgnoreCase(x.media_subtype, y.media_subtype)) return false;
            if (x.body != null and y.body != null and !std.mem.eql(u8, x.body.?, y.body.?)) return false;
        }
        return true;
    }
};

fn trimEol(s: []const u8) []const u8 {
    return std.mem.trimEnd(u8, s, "\r\n");
}

/// Top-level parts according to the mail server: its header parser (headers.zig: split at
/// CRLF, continuation lines trimmed and joined with a space, the last field of a name wins,
/// lookup exact first and then case-insensitive), then MultipartParser.parse on the body after
/// the first CRLF CRLF.
fn mailParts(message: []const u8, out: *Parts) !void {
    const a = out.arena.allocator();
    // The mail parser leaks (duplicate header names and parameters overwrite without freeing),
    // so it gets the arena too.
    const gpa = a;
    const split = std.mem.indexOf(u8, message, "\r\n\r\n") orelse return;
    var fields: std.ArrayList(struct { name: []const u8, value: std.ArrayList(u8) }) = .empty;
    var lines = std.mem.splitSequence(u8, message[0..split], "\r\n");
    while (lines.next()) |line| {
        if (line.len > 998) return;
        if (line.len > 0 and (line[0] == ' ' or line[0] == '\t')) {
            if (fields.items.len > 0) {
                const v = &fields.items[fields.items.len - 1].value;
                try v.append(a, ' ');
                try v.appendSlice(a, std.mem.trim(u8, line, " \t"));
            }
            continue;
        }
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        var value: std.ArrayList(u8) = .empty;
        try value.appendSlice(a, std.mem.trim(u8, line[colon + 1 ..], " \t"));
        try fields.append(a, .{ .name = std.mem.trim(u8, line[0..colon], " \t"), .value = value });
    }
    var ct_value: ?[]const u8 = null;
    for (fields.items) |f| {
        if (std.mem.eql(u8, f.name, "Content-Type")) ct_value = f.value.items;
    }
    if (ct_value == null) {
        for (fields.items) |f| {
            if (std.ascii.eqlIgnoreCase(f.name, "Content-Type")) ct_value = f.value.items;
        }
    }
    var ct = mail.ContentType.parse(gpa, ct_value orelse return) catch return;
    defer ct.deinit();
    const boundary = ct.boundary orelse return;
    var parser = mail.MultipartParser.init(gpa);
    const parts = parser.parse(message[split + 4 ..], boundary) catch return;
    defer parser.freeParts(parts);
    for (parts) |p| {
        const pct = p.content_type;
        const multipart = if (pct) |c| c.isMultipart() else false;
        try out.list.append(a, .{
            .media_type = try a.dupe(u8, if (pct) |c| c.media_type else "text"),
            .media_subtype = try a.dupe(u8, if (pct) |c| c.media_subtype else "plain"),
            .body = if (multipart) null else try a.dupe(u8, trimEol(p.body)),
        });
    }
}

/// Top-level parts according to zig-mime: the children of the top multipart, with their raw
/// (undecoded) bodies.
const Collector = struct {
    parts: *Parts,
    body: std.ArrayList(u8) = .empty,
    current: ?*const mime.Part = null,

    pub fn onEvent(self: *Collector, event: mime.Event) mime.Sink.Error!void {
        self.handle(event) catch return error.Aborted;
    }

    fn handle(self: *Collector, event: mime.Event) !void {
        const a = self.parts.arena.allocator();
        switch (event) {
            .part_begin => |p| if (p.depth == 1 and p.path.len == 1) {
                self.current = p;
                self.body.clearRetainingCapacity();
            },
            .body => |b| if (self.current == b.part) {
                // Raw bytes: the raw view of an encoded part, the content of an identity one.
                if (b.raw or b.part.encoding.isIdentity()) try self.body.appendSlice(a, b.bytes);
            },
            .part_end => |e| if (self.current == e.part) {
                self.current = null;
                try self.parts.list.append(a, .{
                    // The part's header slices die with it: copy them.
                    .media_type = try a.dupe(u8, e.part.content_type.media_type),
                    .media_subtype = try a.dupe(u8, e.part.content_type.media_subtype),
                    .body = if (e.part.content_type.isMultipart()) null else trimEol(try a.dupe(u8, self.body.items)),
                });
            },
            .diagnostic => {},
        }
    }
};

fn mimeParts(message: []const u8, out: *Parts) !void {
    var collector: Collector = .{ .parts = out };
    var scratch: [128 * 1024]u8 = undefined;
    var w = mime.Walker.init(&scratch, mime.Sink.init(&collector), .{ .raw_view = true });
    try w.feed(message);
    try w.finish();
}

// 1. Generated well-formed messages

const Gen = struct {
    r: std.Random,
    out: std.ArrayList(u8) = .empty,
    gpa: std.mem.Allocator,

    fn put(self: *Gen, s: []const u8) !void {
        try self.out.appendSlice(self.gpa, s);
    }

    fn boundary(self: *Gen, buf: []u8) []const u8 {
        const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'()+_,-./:=?";
        const n = self.r.intRangeAtMost(usize, 8, @min(buf.len, 70));
        for (buf[0..n]) |*c| c.* = chars[self.r.uintLessThan(usize, chars.len)];
        buf[0] = 'Z'; // never a prefix of another generated boundary's "--" line
        return buf[0..n];
    }

    /// A multipart body with `n` parts; nested multiparts one level down.
    fn multipart(self: *Gen, b: []const u8, depth: usize) !void {
        const r = self.r;
        if (r.boolean()) try self.put("This is a multi-part message in MIME format.\r\n");
        for (0..r.intRangeAtMost(usize, 1, 5)) |_| {
            try self.put("--");
            try self.put(b);
            try self.put("\r\n");
            switch (r.uintLessThan(u8, if (depth == 0) 4 else 3)) {
                0 => {
                    try self.put("Content-Type: text/plain; charset=utf-8\r\n\r\n");
                    try self.text();
                },
                1 => {
                    try self.put("Content-Type: text/html; charset=\"iso-8859-1\"\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n");
                    try self.text();
                },
                2 => {
                    try self.put("Content-Type: application/octet-stream; name=\"f.bin\"\r\nContent-Transfer-Encoding: base64\r\n" ++
                        "Content-Disposition: attachment; filename=\"f.bin\"\r\n\r\n");
                    var raw: [300]u8 = undefined;
                    const n = r.intRangeAtMost(usize, 1, raw.len);
                    r.bytes(raw[0..n]);
                    var enc: [400]u8 = undefined;
                    const e = std.base64.standard.Encoder.encode(&enc, raw[0..n]);
                    var i: usize = 0;
                    while (i < e.len) : (i += 76) {
                        if (i > 0) try self.put("\r\n");
                        try self.put(e[i..@min(i + 76, e.len)]);
                    }
                },
                else => {
                    var buf: [70]u8 = undefined;
                    const inner = self.boundary(&buf);
                    try self.put("Content-Type: multipart/alternative; boundary=\"");
                    try self.put(inner);
                    try self.put("\"\r\n\r\n");
                    try self.multipart(inner, depth + 1);
                },
            }
            try self.put("\r\n");
        }
        try self.put("--");
        try self.put(b);
        try self.put("--");
        if (r.boolean()) try self.put("\r\n");
    }

    fn text(self: *Gen) !void {
        const words = [_][]const u8{ "hello", "world", "caf=C3=A9", "-", "lorem", "ipsum", "=", "dolor" };
        const lines = self.r.intRangeAtMost(usize, 1, 6);
        for (0..lines) |l| {
            if (l > 0) try self.put("\r\n");
            for (0..self.r.intRangeAtMost(usize, 1, 9)) |w| {
                if (w > 0) try self.put(" ");
                try self.put(words[self.r.uintLessThan(usize, words.len)]);
            }
        }
    }
};

test "well-formed messages parse the same as the mail server" {
    const gpa = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xd1ff);
    for (0..300) |case| {
        var gen: Gen = .{ .r = prng.random(), .gpa = gpa };
        defer gen.out.deinit(gpa);
        var buf: [70]u8 = undefined;
        const b = gen.boundary(&buf);
        try gen.put("From: a@example.com\r\nSubject: diff\r\nContent-Type: multipart/mixed; boundary=\"");
        try gen.put(b);
        try gen.put("\"\r\n\r\n");
        try gen.multipart(b, 0);

        var want = Parts.init(gpa);
        defer want.deinit();
        try mailParts(gen.out.items, &want);
        var got = Parts.init(gpa);
        defer got.deinit();
        try mimeParts(gen.out.items, &got);
        if (want.list.items.len == 0 or !want.eql(&got)) {
            std.debug.print("case {d}: mail {d} parts, zig-mime {d} parts\n{s}\n", .{ case, want.list.items.len, got.list.items.len, gen.out.items });
            want.dump("mail");
            got.dump("zig-mime");
            return error.TestUnexpectedResult;
        }
    }
}

test "Content-Type fields parse the same as the mail server" {
    const gpa = testing.allocator;
    const values = [_][]const u8{
        "multipart/mixed; boundary=\"----=_Part_123\"; charset=utf-8",
        "text/plain",
        "text/plain; charset=us-ascii",
        " Text/HTML ; charset=\"iso-8859-1\" ",
        "multipart/alternative; boundary=simple",
        "application/octet-stream; name=\"a.bin\"; x-unix-mode=0644",
        "multipart/related; type=\"text/html\"; boundary=\"b1_abc\"",
        "image/png;name=x.png",
        "text/",
        "/plain",
    };
    for (values) |v| {
        var want = try mail.ContentType.parse(gpa, v);
        defer want.deinit();
        const got = try mime.ContentType.parse(v);
        try testing.expectEqualStrings(want.media_type, got.media_type);
        try testing.expectEqualStrings(want.media_subtype, got.media_subtype);
        try testing.expectEqualDeep(want.boundary, got.boundary);
        try testing.expectEqualDeep(want.charset, got.charset);
        try testing.expectEqual(want.isMultipart(), got.isMultipart());
    }
    for ([_][]const u8{ "text", "" }) |v| {
        try testing.expectError(error.InvalidContentType, mail.ContentType.parse(gpa, v));
        try testing.expectError(error.InvalidContentType, mime.ContentType.parse(v));
    }
}

// 2. The evasion corpus

const Expect = struct { file: []const u8, agree: bool };

/// Whether the mail server's parser sees the same top-level parts. Every disagreement is
/// intentional on the zig-mime side; the reasons:
///
/// - no-header part: a part that starts with its blank line (no header fields) loses its body
///   in the mail parser, which looks for CRLF CRLF inside the part and so takes the whole part
///   for headers. RFC 2046 allows such parts. This alone explains the entries marked so.
const corpus = [_]Expect{
    // The mail parser needs CRLF CRLF after the headers and CRLF after a delimiter.
    .{ .file = "bare_lf", .agree = false },
    .{ .file = "mixed_line_endings", .agree = false },
    // no-header part.
    .{ .file = "missing_final_boundary", .agree = false },
    // no-header part (mail keeps the last boundary parameter, which is the real one here).
    .{ .file = "duplicate_boundary_first_decoy", .agree = false },
    // Mail keeps the last boundary parameter, the decoy, and finds no parts.
    .{ .file = "duplicate_boundary_last_decoy", .agree = false },
    // no-header part (mail keeps the last Content-Type field, the multipart one here).
    .{ .file = "duplicate_content_type", .agree = false },
    // Mail splits parameters at every ';', so the decoy inside the quoted value wins.
    .{ .file = "boundary_in_quoted_param", .agree = false },
    // Mail does not read RFC 2231 continuations and finds no boundary.
    .{ .file = "boundary_rfc2231", .agree = false },
    // Mail stops at the close delimiter; zig-mime reopens the multipart.
    .{ .file = "part_after_close", .agree = false },
    // Mail splits the top level at the inner delimiters too; zig-mime gives them to the
    // innermost open multipart.
    .{ .file = "nested_same_boundary", .agree = false },
    // no-header part (both split at the suffixed delimiter).
    .{ .file = "boundary_suffix", .agree = false },
    // Mail reads headers until CRLF CRLF, swallowing the base64 body into the header map.
    .{ .file = "missing_header_separator", .agree = false },
    // Mail takes the nested part's delimiter and headers for the part's own headers, so the
    // last Content-Type (the attachment's) wins over multipart/mixed.
    .{ .file = "multipart_without_blank_line", .agree = false },
    .{ .file = "encoded_container", .agree = true },
    .{ .file = "rfc822_base64", .agree = true },
    // Mail refuses nesting deeper than 10 levels and returns no parts.
    .{ .file = "deep_nesting", .agree = false },
    // no-header part (zig-mime's part limit is not set here, so both see every part).
    .{ .file = "part_limit", .agree = false },
    .{ .file = "header_padding", .agree = true },
    .{ .file = "duplicate_cte", .agree = true },
    .{ .file = "base64_after_padding", .agree = true },
    .{ .file = "base64_junk", .agree = true },
    .{ .file = "qp_obfuscated", .agree = true },
    // Mail rejects boundaries over 70 characters and returns no parts.
    .{ .file = "long_boundary", .agree = false },
    .{ .file = "folded_boundary_param", .agree = true },
    .{ .file = "case_and_spacing", .agree = true },
    .{ .file = "filename_conflict", .agree = true },
    .{ .file = "mbox_from_line", .agree = true },
};

test "a part without header fields keeps its body (the mail parser drops it)" {
    const message = "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\r\nhello\r\n--b--\r\n";
    var want = Parts.init(testing.allocator);
    defer want.deinit();
    try mailParts(message, &want);
    var got = Parts.init(testing.allocator);
    defer got.deinit();
    try mimeParts(message, &got);
    try testing.expectEqualStrings("", want.list.items[0].body.?);
    try testing.expectEqualStrings("hello", got.list.items[0].body.?);
}

test "evasion corpus: agreement with the mail server is pinned per sample" {
    const gpa = testing.allocator;
    var flipped: usize = 0;
    inline for (corpus) |c| {
        const data = @embedFile("evasion/" ++ c.file ++ ".eml");
        var want = Parts.init(gpa);
        defer want.deinit();
        try mailParts(data, &want);
        var got = Parts.init(gpa);
        defer got.deinit();
        try mimeParts(data, &got);
        const agree = want.eql(&got);
        if (agree != c.agree) {
            std.debug.print("{s}: expected agree={}, mail {d} parts, zig-mime {d} parts\n", .{ c.file, c.agree, want.list.items.len, got.list.items.len });
            want.dump("mail");
            got.dump("zig-mime");
            flipped += 1;
        }
    }
    try testing.expectEqual(@as(usize, 0), flipped);
}

//! Header blocks: in-place unfolding, field lookup and Content-Type parameters.
//!
//! Nothing here allocates. A header block is unfolded in the buffer that holds it, and every
//! parsed value is a slice of that block.
const std = @import("std");

pub const Field = struct {
    name: []const u8,
    /// Unfolded value with surrounding whitespace trimmed.
    value: []const u8,
};

/// An unfolded header block: one `name:value\n` line per field, in message order.
pub const Headers = struct {
    block: []const u8 = "",

    pub fn iterator(self: Headers) Iterator {
        return .{ .rest = self.block };
    }

    /// Value of the first field called `name` (case-insensitive).
    pub fn get(self: Headers, name: []const u8) ?[]const u8 {
        var it = self.iterator();
        while (it.next()) |f| {
            if (std.ascii.eqlIgnoreCase(f.name, name)) return f.value;
        }
        return null;
    }

    /// Number of fields called `name` (case-insensitive).
    pub fn count(self: Headers, name: []const u8) usize {
        var n: usize = 0;
        var it = self.iterator();
        while (it.next()) |f| {
            if (std.ascii.eqlIgnoreCase(f.name, name)) n += 1;
        }
        return n;
    }

    pub const Iterator = struct {
        rest: []const u8,

        pub fn next(self: *Iterator) ?Field {
            while (self.rest.len > 0) {
                const end = std.mem.indexOfScalar(u8, self.rest, '\n') orelse self.rest.len;
                const line = self.rest[0..end];
                self.rest = self.rest[@min(end + 1, self.rest.len)..];
                const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
                return .{ .name = line[0..colon], .value = trimWs(line[colon + 1 ..]) };
            }
            return null;
        }
    };
};

/// Position of the ':' ending a field name, or null when `line` does not start a header field.
/// A field name is one or more printable ASCII characters other than ':' and may be followed by
/// spaces or tabs before the colon (RFC 5322 obsolete syntax).
pub fn fieldColon(line: []const u8) ?usize {
    var i: usize = 0;
    while (i < line.len and isNameChar(line[i])) : (i += 1) {}
    if (i == 0) return null;
    while (i < line.len and (line[i] == ' ' or line[i] == '\t')) : (i += 1) {}
    if (i < line.len and line[i] == ':') return i;
    return null;
}

pub fn isNameChar(c: u8) bool {
    return c > ' ' and c < 0x7f and c != ':';
}

/// Unfolds a raw header block in place and returns the normalized block, a prefix of `raw`.
///
/// `raw` holds header lines ending in CRLF or bare LF. Continuation lines (starting with a space
/// or tab) are joined to the field before them by removing the line break and keeping the
/// whitespace, as RFC 5322 section 2.2.3 specifies. Lines that are neither fields nor
/// continuations are dropped. Each field comes out as `name:value\n`.
pub fn unfold(raw: []u8) []u8 {
    var w: usize = 0;
    var r: usize = 0;
    var in_field = false;
    while (r < raw.len) {
        const nl = std.mem.indexOfScalarPos(u8, raw, r, '\n') orelse raw.len;
        var line_end = nl;
        if (line_end > r and raw[line_end - 1] == '\r') line_end -= 1;
        const start = r;
        r = @min(nl + 1, raw.len);
        if (line_end == start) continue;
        if (raw[start] == ' ' or raw[start] == '\t') {
            if (!in_field) continue;
            w -= 1; // reopen the previous field: drop its '\n'
            std.mem.copyForwards(u8, raw[w..], raw[start..line_end]);
            w += line_end - start;
            w += terminate(raw, w);
            continue;
        }
        const colon = fieldColon(raw[start..line_end]) orelse {
            in_field = false;
            continue;
        };
        var name_end = start + colon;
        while (name_end > start and (raw[name_end - 1] == ' ' or raw[name_end - 1] == '\t')) name_end -= 1;
        std.mem.copyForwards(u8, raw[w..], raw[start..name_end]);
        w += name_end - start;
        raw[w] = ':';
        w += 1;
        const value_start = start + colon + 1;
        std.mem.copyForwards(u8, raw[w..], raw[value_start..line_end]);
        w += line_end - value_start;
        w += terminate(raw, w);
        in_field = true;
    }
    return raw[0..w];
}

/// Writes the '\n' ending a field, except after a final line that had no line break of its own
/// (the block is full then, and the iterator does not need it).
fn terminate(raw: []u8, w: usize) usize {
    if (w == raw.len) return 0;
    raw[w] = '\n';
    return 1;
}

pub fn trimWs(s: []const u8) []const u8 {
    return std.mem.trim(u8, s, " \t\r\n");
}

/// One `name=value` parameter of a structured header field.
pub const Param = struct {
    name: []const u8,
    /// The value without its surrounding quotes. A quoted value keeps its backslash escapes;
    /// `unquote` removes them.
    value: []const u8,
    quoted: bool,
};

/// Iterates the `; name=value` parameters of a Content-Type or Content-Disposition value.
/// Quoted strings may contain ';' and '=', and parenthesised comments are skipped, so a
/// parameter hidden inside another parameter's quoted value is never reported.
pub const ParamIterator = struct {
    rest: []const u8,

    pub fn next(self: *ParamIterator) ?Param {
        while (true) {
            self.skipSeparators();
            if (self.rest.len == 0) return null;
            var i: usize = 0;
            while (i < self.rest.len and self.rest[i] != '=' and self.rest[i] != ';') : (i += 1) {}
            const name = trimWs(self.rest[0..i]);
            if (i == self.rest.len or self.rest[i] == ';') {
                // A bare token without a value: not a parameter.
                self.rest = self.rest[i..];
                continue;
            }
            self.rest = self.rest[i + 1 ..];
            while (self.rest.len > 0 and (self.rest[0] == ' ' or self.rest[0] == '\t')) self.rest = self.rest[1..];
            if (self.rest.len > 0 and self.rest[0] == '"') {
                var j: usize = 1;
                while (j < self.rest.len and self.rest[j] != '"') : (j += 1) {
                    if (self.rest[j] == '\\' and j + 1 < self.rest.len) j += 1;
                }
                const value = self.rest[1..@min(j, self.rest.len)];
                self.rest = self.rest[@min(j + 1, self.rest.len)..];
                // Anything between the closing quote and the next ';' is ignored.
                const semi = std.mem.indexOfScalar(u8, self.rest, ';') orelse self.rest.len;
                self.rest = self.rest[semi..];
                if (name.len == 0) continue;
                return .{ .name = name, .value = value, .quoted = true };
            }
            const semi = std.mem.indexOfScalar(u8, self.rest, ';') orelse self.rest.len;
            var value = self.rest[0..semi];
            if (std.mem.indexOfScalar(u8, value, '(')) |paren| value = value[0..paren];
            self.rest = self.rest[semi..];
            if (name.len == 0) continue;
            return .{ .name = name, .value = trimWs(value), .quoted = false };
        }
    }

    fn skipSeparators(self: *ParamIterator) void {
        while (self.rest.len > 0) {
            switch (self.rest[0]) {
                ' ', '\t', '\r', '\n', ';' => self.rest = self.rest[1..],
                '(' => self.rest = self.rest[commentEnd(self.rest)..],
                else => return,
            }
        }
    }
};

/// Length of the (possibly nested) comment at the start of `s`, including its parentheses.
fn commentEnd(s: []const u8) usize {
    var depth: usize = 0;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        switch (s[i]) {
            '\\' => i += 1,
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if (depth == 0) return i + 1;
            },
            else => {},
        }
    }
    return s.len;
}

/// Removes the backslash escapes of a quoted-string value into `out` (at least `value.len`
/// bytes) and returns the result.
pub fn unquote(value: []const u8, out: []u8) []u8 {
    var w: usize = 0;
    var i: usize = 0;
    while (i < value.len) : (i += 1) {
        var c = value[i];
        if (c == '\\' and i + 1 < value.len) {
            i += 1;
            c = value[i];
        }
        out[w] = c;
        w += 1;
    }
    return out[0..w];
}

/// A parsed Content-Type value. Every slice points into the value it was parsed from.
pub const ContentType = struct {
    media_type: []const u8,
    media_subtype: []const u8,
    /// The raw parameter list after the media type.
    params: []const u8 = "",
    /// First `boundary` parameter, quotes removed, escapes intact.
    boundary: ?[]const u8 = null,
    /// First `charset` parameter.
    charset: ?[]const u8 = null,

    /// The RFC 2045 default for a part without a usable Content-Type.
    pub const default: ContentType = .{ .media_type = "text", .media_subtype = "plain" };
    /// The RFC 2046 default for a part of a multipart/digest.
    pub const digest_default: ContentType = .{ .media_type = "message", .media_subtype = "rfc822" };

    pub const ParseError = error{InvalidContentType};

    /// Parses `type/subtype; name=value; ...`. Only a missing '/' is an error, matching the mail
    /// server's ContentType.parse.
    pub fn parse(value: []const u8) ParseError!ContentType {
        var i: usize = 0;
        while (i < value.len and value[i] != ';' and value[i] != '(') : (i += 1) {}
        const type_part = trimWs(value[0..i]);
        const slash = std.mem.indexOfScalar(u8, type_part, '/') orelse return error.InvalidContentType;
        var ct: ContentType = .{
            .media_type = trimWs(type_part[0..slash]),
            .media_subtype = trimWs(type_part[slash + 1 ..]),
            .params = value[i..],
        };
        var it = ct.paramIterator();
        while (it.next()) |p| {
            if (ct.boundary == null and std.ascii.eqlIgnoreCase(p.name, "boundary")) ct.boundary = p.value;
            if (ct.charset == null and std.ascii.eqlIgnoreCase(p.name, "charset")) ct.charset = p.value;
        }
        return ct;
    }

    pub fn paramIterator(self: ContentType) ParamIterator {
        return .{ .rest = self.params };
    }

    pub fn is(self: ContentType, media_type: []const u8, media_subtype: []const u8) bool {
        return std.ascii.eqlIgnoreCase(self.media_type, media_type) and
            std.ascii.eqlIgnoreCase(self.media_subtype, media_subtype);
    }

    pub fn isMultipart(self: ContentType) bool {
        return std.ascii.eqlIgnoreCase(self.media_type, "multipart");
    }

    /// message/rfc822 and message/global carry a complete embedded message.
    pub fn isEmbeddedMessage(self: ContentType) bool {
        return self.is("message", "rfc822") or self.is("message", "global");
    }
};

/// The parameter called `name` (case-insensitive), first occurrence.
pub fn findParam(params: []const u8, name: []const u8) ?Param {
    var it: ParamIterator = .{ .rest = params };
    while (it.next()) |p| {
        if (std.ascii.eqlIgnoreCase(p.name, name)) return p;
    }
    return null;
}

/// Number of parameters called `name` (case-insensitive).
pub fn countParam(params: []const u8, name: []const u8) usize {
    var n: usize = 0;
    var it: ParamIterator = .{ .rest = params };
    while (it.next()) |p| {
        if (std.ascii.eqlIgnoreCase(p.name, name)) n += 1;
    }
    return n;
}

/// A parsed Content-Disposition value.
pub const Disposition = struct {
    kind: Kind = .none,
    /// The raw parameter list after the disposition type.
    params: []const u8 = "",

    pub const Kind = enum { none, @"inline", attachment, other };

    pub fn parse(value: []const u8) Disposition {
        const semi = std.mem.indexOfScalar(u8, value, ';') orelse value.len;
        const t = trimWs(value[0..semi]);
        const kind: Kind = if (std.ascii.eqlIgnoreCase(t, "inline"))
            .@"inline"
        else if (std.ascii.eqlIgnoreCase(t, "attachment"))
            .attachment
        else
            .other;
        return .{ .kind = kind, .params = value[semi..] };
    }
};

/// The mail server's boundary limits (RFC 2046 section 5.1.1).
pub const max_rfc_boundary_len = 70;

pub const BoundaryError = error{ BoundaryTooLong, InvalidBoundary };

/// The mail server's boundary validation: at most 70 characters, all from the RFC 2046 bchars
/// set except space. The walker reports a failure as `boundary_invalid` and still splits on the
/// boundary, because mail clients do.
pub fn validateBoundary(boundary: []const u8) BoundaryError!void {
    if (boundary.len > max_rfc_boundary_len) return error.BoundaryTooLong;
    for (boundary) |c| {
        const ok = std.ascii.isAlphanumeric(c) or switch (c) {
            '\'', '(', ')', '+', '_', ',', '-', '.', '/', ':', '=', '?' => true,
            else => false,
        };
        if (!ok) return error.InvalidBoundary;
    }
}

const testing = std.testing;

// Ported from the mail server (packages/zig/src/message/mime.zig, "parse content type").
test "mail port: parse content type" {
    const ct = try ContentType.parse("multipart/mixed; boundary=\"----=_Part_123\"; charset=utf-8");
    try testing.expectEqualStrings("multipart", ct.media_type);
    try testing.expectEqualStrings("mixed", ct.media_subtype);
    try testing.expectEqualStrings("----=_Part_123", ct.boundary.?);
    try testing.expectEqualStrings("utf-8", ct.charset.?);
    try testing.expect(ct.isMultipart());
}

test "mail port: a type without a slash is invalid" {
    try testing.expectError(error.InvalidContentType, ContentType.parse("text"));
    try testing.expectError(error.InvalidContentType, ContentType.parse(""));
}

// Ported from the mail server's MultipartParser tests and tests/security_test.zig.
test "mail port: boundary validation" {
    try testing.expectError(error.BoundaryTooLong, validateBoundary(&@as([71]u8, @splat('a'))));
    try testing.expectError(error.BoundaryTooLong, validateBoundary(&@as([1000]u8, @splat('a'))));
    try testing.expectError(error.InvalidBoundary, validateBoundary("test boundary"));
    try validateBoundary(&@as([70]u8, @splat('a')));
    try validateBoundary("----=_Part_123");
    try validateBoundary("'()+_,-./:=?09azAZ");
}

test "Content-Disposition" {
    const d = Disposition.parse("Attachment; filename=\"a.txt\"");
    try testing.expectEqual(Disposition.Kind.attachment, d.kind);
    try testing.expectEqualStrings("a.txt", findParam(d.params, "FILENAME").?.value);
    try testing.expectEqual(Disposition.Kind.@"inline", Disposition.parse("inline").kind);
    try testing.expectEqual(@as(usize, 2), countParam("; a=1; A=\"2\"; b=3", "a"));
}

test "unfold joins continuation lines and normalises line endings" {
    var raw = "Subject: a long\r\n  subject\r\nX-Bare: lf\nFrom : x@y\r\n\tcontinued\r\n".*;
    const block = unfold(&raw);
    try testing.expectEqualStrings("Subject: a long  subject\nX-Bare: lf\nFrom: x@y\tcontinued\n", block);
    const h: Headers = .{ .block = block };
    try testing.expectEqualStrings("a long  subject", h.get("subject").?);
    try testing.expectEqualStrings("x@y\tcontinued", h.get("FROM").?);
    try testing.expectEqual(@as(usize, 1), h.count("x-bare"));
}

test "unfold handles a final line without a line break" {
    var raw = "A: 1\r\nB: 2".*;
    const block = unfold(&raw);
    try testing.expectEqualStrings("A: 1\nB: 2\n", block);
    try testing.expectEqualStrings("2", (Headers{ .block = block }).get("b").?);
    var full = "B:2".*;
    try testing.expectEqualStrings("B:2", unfold(&full));
    var cont = "A: 1\n 2".*;
    try testing.expectEqualStrings("A: 1 2\n", unfold(&cont));
}

test "unfold drops orphan continuations and non-field lines" {
    var raw = "  orphan\r\nnot a field\r\nA: 1\r\n".*;
    try testing.expectEqualStrings("A: 1\n", unfold(&raw));
}

test "parameters respect quoted strings and comments" {
    const ct = try ContentType.parse("multipart/mixed (comment; boundary=no); x=\"; boundary=fake\"; boundary=\"real;one\"");
    try testing.expectEqualStrings("real;one", ct.boundary.?);
    var it = ct.paramIterator();
    try testing.expectEqualStrings("x", it.next().?.name);
    try testing.expectEqualStrings("boundary", it.next().?.name);
    try testing.expectEqual(@as(?Param, null), it.next());
}

test "unquoted values stop at a comment" {
    const ct = try ContentType.parse("text/plain; charset=us-ascii (Plain text)");
    try testing.expectEqualStrings("us-ascii", ct.charset.?);
}

test "unquote removes escapes" {
    var buf: [16]u8 = undefined;
    try testing.expectEqualStrings("a\"b\\c", unquote("a\\\"b\\\\c", &buf));
}

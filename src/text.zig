//! Header text decoding into UTF-8: RFC 2047 encoded words, RFC 2231 parameter values and
//! continuations, and the charsets mail actually uses. Output goes into a caller buffer; nothing
//! allocates, and running out of room is reported, never silent.
const std = @import("std");
const headers = @import("headers.zig");
const base64 = @import("decode/base64.zig");

pub const Flags = packed struct(u8) {
    /// The output buffer was too small; the result is a prefix of the decoded text.
    truncated: bool = false,
    /// A charset other than UTF-8, US-ASCII, ISO-8859-1 and Windows-1252; bytes were copied
    /// unconverted.
    unsupported_charset: bool = false,
    /// Something looked like an encoded word or an RFC 2231 value but was malformed; it was kept
    /// literally or decoded as far as possible.
    malformed: bool = false,
    _: u5 = 0,

    pub fn merge(a: Flags, b: Flags) Flags {
        return .{
            .truncated = a.truncated or b.truncated,
            .unsupported_charset = a.unsupported_charset or b.unsupported_charset,
            .malformed = a.malformed or b.malformed,
        };
    }
};

pub const Result = struct {
    text: []u8,
    flags: Flags = .{},
};

pub const Charset = enum {
    utf8,
    ascii,
    latin1,
    windows1252,
    other,

    pub fn parse(name: []const u8) Charset {
        // An RFC 2231 language suffix ("utf-8*en") is not part of the name.
        const n = if (std.mem.indexOfScalar(u8, name, '*')) |star| name[0..star] else name;
        const map = .{
            .{ "utf-8", Charset.utf8 },         .{ "utf8", Charset.utf8 },
            .{ "us-ascii", Charset.ascii },     .{ "ascii", Charset.ascii },
            .{ "iso-8859-1", Charset.latin1 },  .{ "iso8859-1", Charset.latin1 },
            .{ "iso_8859-1", Charset.latin1 },  .{ "latin1", Charset.latin1 },
            .{ "l1", Charset.latin1 },          .{ "windows-1252", Charset.windows1252 },
            .{ "cp1252", Charset.windows1252 },
        };
        inline for (map) |m| {
            if (std.ascii.eqlIgnoreCase(n, m[0])) return m[1];
        }
        return .other;
    }
};

/// Windows-1252 code points for 0x80..0x9f (0 where the byte is undefined; it maps to itself).
const cp1252_high = [32]u16{
    0x20ac, 0,      0x201a, 0x0192, 0x201e, 0x2026, 0x2020, 0x2021,
    0x02c6, 0x2030, 0x0160, 0x2039, 0x0152, 0,      0x017d, 0,
    0,      0x2018, 0x2019, 0x201c, 0x201d, 0x2022, 0x2013, 0x2014,
    0x02dc, 0x2122, 0x0161, 0x203a, 0x0153, 0,      0x017e, 0x0178,
};

/// Writes `raw` in `charset` to `out` as UTF-8 starting at `w.*`.
fn appendCharset(charset: Charset, raw: []const u8, out: []u8, w: *usize, flags: *Flags) void {
    switch (charset) {
        .utf8, .ascii => append(raw, out, w, flags),
        .other => {
            flags.unsupported_charset = true;
            append(raw, out, w, flags);
        },
        .latin1, .windows1252 => for (raw) |b| {
            var cp: u21 = b;
            if (charset == .windows1252 and b >= 0x80 and b < 0xa0 and cp1252_high[b - 0x80] != 0) {
                cp = cp1252_high[b - 0x80];
            }
            var buf: [4]u8 = undefined;
            const n = std.unicode.utf8Encode(cp, &buf) catch unreachable;
            if (out.len - w.* < n) {
                flags.truncated = true;
                return;
            }
            @memcpy(out[w.*..][0..n], buf[0..n]);
            w.* += n;
        },
    }
}

fn append(bytes: []const u8, out: []u8, w: *usize, flags: *Flags) void {
    const n = @min(bytes.len, out.len - w.*);
    if (n < bytes.len) flags.truncated = true;
    @memcpy(out[w.*..][0..n], bytes[0..n]);
    w.* += n;
}

/// Longest decoded encoded word; longer ones are decoded in part and flagged.
const word_cap = 1024;

/// Decodes the RFC 2047 encoded words in `in` (an unstructured header value or a parameter
/// value) into UTF-8. Text outside encoded words is copied as it is, and whitespace between two
/// adjacent encoded words is dropped. Malformed words stay literal and set `malformed`.
pub fn decodeWords(in: []const u8, out: []u8) Result {
    var flags: Flags = .{};
    var w: usize = 0;
    var i: usize = 0;
    // Output position just after the last encoded word, while only whitespace followed it.
    var after_word: ?usize = null;
    while (i < in.len) {
        if (in[i] == '=' and i + 1 < in.len and in[i + 1] == '?') {
            if (parseWord(in[i..])) |word| {
                if (after_word) |p| w = p;
                var raw: [word_cap]u8 = undefined;
                const decoded = word.decode(&raw, &flags);
                appendCharset(Charset.parse(word.charset), decoded, out, &w, &flags);
                after_word = w;
                i += word.len;
                continue;
            }
            flags.malformed = true;
        }
        const c = in[i];
        if (c != ' ' and c != '\t' and c != '\r' and c != '\n') after_word = null;
        append(in[i .. i + 1], out, &w, &flags);
        i += 1;
    }
    return .{ .text = out[0..w], .flags = flags };
}

const Word = struct {
    charset: []const u8,
    b: bool,
    text: []const u8,
    /// Length of the whole word including "=?" and "?=".
    len: usize,

    fn decode(self: Word, raw: *[word_cap]u8, flags: *Flags) []u8 {
        var src = self.text;
        if (self.b) {
            // Each 4 characters make 3 bytes, so this much input always fits.
            const max_in = base64.Decoder.maxInput(raw.len);
            if (src.len > max_in) {
                src = src[0..max_in];
                flags.truncated = true;
            }
            var d: base64.Decoder = .{};
            var n = d.decode(src, raw);
            n += d.finish(raw[n..]);
            if (d.flags.invalid_input) flags.malformed = true;
            return raw[0..n];
        }
        var n: usize = 0;
        var i: usize = 0;
        while (i < src.len) : (i += 1) {
            if (n == raw.len) {
                flags.truncated = true;
                break;
            }
            const c = src[i];
            if (c == '_') {
                raw[n] = ' ';
            } else if (c == '=' and i + 2 < src.len and hex(src[i + 1]) != null and hex(src[i + 2]) != null) {
                raw[n] = (hex(src[i + 1]).? << 4) | hex(src[i + 2]).?;
                i += 2;
            } else {
                if (c == '=') flags.malformed = true;
                raw[n] = c;
            }
            n += 1;
        }
        return raw[0..n];
    }
};

/// Parses `=?charset?B|Q?text?=` at the start of `s`.
fn parseWord(s: []const u8) ?Word {
    if (s.len < 8 or s[0] != '=' or s[1] != '?') return null;
    const q1 = std.mem.indexOfScalarPos(u8, s, 2, '?') orelse return null;
    if (q1 == 2 or q1 + 2 >= s.len or s[q1 + 2] != '?') return null;
    const charset = s[2..q1];
    for (charset) |c| if (c <= ' ' or c >= 0x7f) return null;
    const b = switch (s[q1 + 1]) {
        'b', 'B' => true,
        'q', 'Q' => false,
        else => return null,
    };
    const text_start = q1 + 3;
    const end = std.mem.indexOfPos(u8, s, text_start, "?=") orelse return null;
    const text = s[text_start..end];
    for (text) |c| if (c == ' ' or c == '\t' or c == '\r' or c == '\n') return null;
    return .{ .charset = charset, .b = b, .text = text, .len = end + 2 };
}

fn hex(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'A'...'F' => c - 'A' + 10,
        'a'...'f' => c - 'a' + 10,
        else => null,
    };
}

/// Highest RFC 2231 continuation index followed.
const max_sections = 256;
/// Longest raw (pre-conversion) parameter value assembled from RFC 2231 sections.
const param_cap = 2048;

/// Finds parameter `name` in a parameter list and decodes it into UTF-8: RFC 2231 extended
/// values (`name*=charset'lang'%XX`) and continuations (`name*0=`, `name*1*=`, ...) take
/// precedence over a plain `name=`, as RFC 2231 aware clients do. A plain value may carry
/// RFC 2047 encoded words, which many senders put in filenames; they are decoded too.
/// Returns null when the parameter is absent.
pub fn decodeParam(params: []const u8, name: []const u8, out: []u8) ?Result {
    if (decodeExtendedParam(params, name, out)) |r| return r;
    var flags: Flags = .{};
    var raw: [param_cap]u8 = undefined;
    var it: headers.ParamIterator = .{ .rest = params };
    while (it.next()) |p| {
        if (!std.ascii.eqlIgnoreCase(p.name, name)) continue;
        const n = unquoteInto(p, &raw, &flags);
        const r = decodeWords(raw[0..n], out);
        return .{ .text = r.text, .flags = r.flags.merge(flags) };
    }
    return null;
}

/// Only the RFC 2231 forms of parameter `name` (`name*=` or `name*0=`, `name*1*=`, ...),
/// decoded to UTF-8; null when the parameter has none.
pub fn decodeExtendedParam(params: []const u8, name: []const u8, out: []u8) ?Result {
    var flags: Flags = .{};
    var raw: [param_cap]u8 = undefined;
    var raw_len: usize = 0;
    var charset: Charset = .ascii;
    var found_extended = false;

    // A single extended value: name*=charset'lang'value.
    if (findSection(params, name, null)) |p| {
        found_extended = true;
        const v = splitCharset(p.value, &charset, &flags);
        raw_len = percentDecode(v, &raw, &flags);
    } else {
        var index: usize = 0;
        while (index < max_sections) : (index += 1) {
            const p = findSection(params, name, index) orelse break;
            found_extended = true;
            var value = p.value;
            const encoded = p.name[p.name.len - 1] == '*';
            if (encoded and index == 0) value = splitCharset(value, &charset, &flags);
            if (encoded) {
                raw_len += percentDecode(value, raw[raw_len..], &flags);
            } else {
                raw_len += unquoteInto(p, raw[raw_len..], &flags);
            }
        }
    }
    if (!found_extended) return null;
    var w: usize = 0;
    appendCharset(charset, raw[0..raw_len], out, &w, &flags);
    return .{ .text = out[0..w], .flags = flags };
}

/// The parameter `name*` (index null) or `name*<index>` / `name*<index>*`.
fn findSection(params: []const u8, name: []const u8, index: ?usize) ?headers.Param {
    var it: headers.ParamIterator = .{ .rest = params };
    while (it.next()) |p| {
        if (p.name.len < name.len + 1) continue;
        if (!std.ascii.eqlIgnoreCase(p.name[0..name.len], name) or p.name[name.len] != '*') continue;
        var rest = p.name[name.len + 1 ..];
        if (index) |want| {
            if (rest.len > 0 and rest[rest.len - 1] == '*') rest = rest[0 .. rest.len - 1];
            const got = std.fmt.parseInt(usize, rest, 10) catch continue;
            if (got == want) return p;
        } else if (rest.len == 0) {
            return p;
        }
    }
    return null;
}

/// Strips `charset'lang'` from an extended value and records the charset.
fn splitCharset(value: []const u8, charset: *Charset, flags: *Flags) []const u8 {
    const q1 = std.mem.indexOfScalar(u8, value, '\'') orelse {
        flags.malformed = true;
        return value;
    };
    const q2 = std.mem.indexOfScalarPos(u8, value, q1 + 1, '\'') orelse {
        flags.malformed = true;
        return value;
    };
    charset.* = if (q1 == 0) .ascii else Charset.parse(value[0..q1]);
    return value[q2 + 1 ..];
}

fn percentDecode(value: []const u8, out: []u8, flags: *Flags) usize {
    var w: usize = 0;
    var i: usize = 0;
    while (i < value.len) : (i += 1) {
        if (w == out.len) {
            flags.truncated = true;
            break;
        }
        const c = value[i];
        if (c == '%' and i + 2 < value.len and hex(value[i + 1]) != null and hex(value[i + 2]) != null) {
            out[w] = (hex(value[i + 1]).? << 4) | hex(value[i + 2]).?;
            i += 2;
        } else {
            if (c == '%') flags.malformed = true;
            out[w] = c;
        }
        w += 1;
    }
    return w;
}

fn unquoteInto(p: headers.Param, out: []u8, flags: *Flags) usize {
    var w: usize = 0;
    var i: usize = 0;
    while (i < p.value.len) : (i += 1) {
        if (w == out.len) {
            flags.truncated = true;
            break;
        }
        var c = p.value[i];
        if (p.quoted and c == '\\' and i + 1 < p.value.len) {
            i += 1;
            c = p.value[i];
        }
        out[w] = c;
        w += 1;
    }
    return w;
}

const testing = std.testing;

test "RFC 2047 encoded words" {
    var out: [128]u8 = undefined;
    try testing.expectEqualStrings("café.pdf", decodeWords("=?UTF-8?B?Y2Fmw6kucGRm?=", &out).text);
    try testing.expectEqualStrings("café crème", decodeWords("=?iso-8859-1?Q?caf=E9_cr=E8me?=", &out).text);
    // Whitespace between adjacent encoded words disappears, around plain text it stays.
    try testing.expectEqualStrings("ab c", decodeWords("=?utf-8?q?a?= \t =?utf-8?q?b?= c", &out).text);
    try testing.expectEqualStrings("x a y", decodeWords("x =?utf-8?q?a?= y", &out).text);
    // A UTF-8 character split across two words is joined.
    try testing.expectEqualStrings("é", decodeWords("=?utf-8?q?=C3?= =?utf-8?q?=A9?=", &out).text);
    // Language suffix, Windows-1252 smart quotes.
    try testing.expectEqualStrings("\u{201c}hi\u{201d}", decodeWords("=?windows-1252*en?Q?=93hi=94?=", &out).text);
    const bad = decodeWords("=?utf-8?x?abc?= =?broken", &out);
    try testing.expectEqualStrings("=?utf-8?x?abc?= =?broken", bad.text);
    try testing.expect(bad.flags.malformed);
    const other = decodeWords("=?koi8-r?B?8NLJ18XU?=", &out);
    try testing.expect(other.flags.unsupported_charset);
}

test "RFC 2047 output is bounded" {
    var out: [4]u8 = undefined;
    const r = decodeWords("=?utf-8?q?abcdef?=", &out);
    try testing.expectEqualStrings("abcd", r.text);
    try testing.expect(r.flags.truncated);
}

test "RFC 2231 continuations and charsets" {
    var out: [128]u8 = undefined;
    // Sections arrive out of order and mix encoded and plain segments.
    const params = "; filename*1*=%20report; filename*0*=utf-8'en'caf%C3%A9; filename*2=\".pdf\"; filename=\"fallback.pdf\"";
    const r = decodeParam(params, "filename", &out).?;
    try testing.expectEqualStrings("café report.pdf", r.text);
    try testing.expectEqual(Flags{}, r.flags);

    try testing.expectEqualStrings("naïve.txt", decodeParam("; name*=iso-8859-1''na%EFve.txt", "name", &out).?.text);
    try testing.expectEqualStrings("a b", decodeParam("; title*0=\"a\"; title*1=\" b\"", "title", &out).?.text);
    try testing.expectEqualStrings("café.pdf", decodeParam("; filename=\"=?UTF-8?B?Y2Fmw6kucGRm?=\"", "filename", &out).?.text);
    try testing.expectEqualStrings("x\"y", decodeParam("; filename=\"x\\\"y\"", "filename", &out).?.text);
    try testing.expectEqual(@as(?Result, null), decodeParam("; filenamex=1; other=2", "filename", &out));
}

//! SIMD search for boundary delimiter candidates.
//!
//! A delimiter line starts right after a line feed, so every delimiter is preceded by "\n--" (the
//! CR of a CRLF ending sits before the LF and does not matter for the search). The walker only
//! stops at those positions; everything between two candidates is body content and is passed on
//! without being looked at byte by byte.
const std = @import("std");

/// Vector width: two native registers per step, so the three shifted loads and compares of one
/// step overlap well on both x86-64 and aarch64.
const lanes = 2 * (std.simd.suggestVectorLength(u8) orelse 16);
const V = @Vector(lanes, u8);
const Mask = @Int(.unsigned, lanes);

/// Index of the first '\n' in `data` that may start a delimiter line: it is followed by "--", or
/// by a prefix of "--" cut off by the end of `data` (the caller decides those with more input).
pub fn findCandidate(data: []const u8) ?usize {
    var i: usize = 0;
    if (data.len >= lanes + 2) {
        const nl: V = @splat('\n');
        const dash: V = @splat('-');
        while (i + lanes + 2 <= data.len) : (i += lanes) {
            const a: V = data[i..][0..lanes].*;
            const lf: Mask = @bitCast(a == nl);
            if (lf == 0) continue;
            const b: V = data[i + 1 ..][0..lanes].*;
            const c: V = data[i + 2 ..][0..lanes].*;
            const m = lf & @as(Mask, @bitCast(b == dash)) & @as(Mask, @bitCast(c == dash));
            if (m != 0) return i + @ctz(m);
        }
    }
    while (i < data.len) : (i += 1) {
        if (data[i] != '\n') continue;
        if (i + 1 < data.len and data[i + 1] != '-') continue;
        if (i + 2 < data.len and data[i + 2] != '-') continue;
        return i;
    }
    return null;
}

fn findCandidateScalar(data: []const u8) ?usize {
    for (data, 0..) |c, i| {
        if (c != '\n') continue;
        if (i + 1 < data.len and data[i + 1] != '-') continue;
        if (i + 2 < data.len and data[i + 2] != '-') continue;
        return i;
    }
    return null;
}

test "findCandidate finds LF and CRLF delimiters" {
    try std.testing.expectEqual(@as(?usize, 5), findCandidate("hello\n--b"));
    try std.testing.expectEqual(@as(?usize, 6), findCandidate("hello\r\n--b"));
    try std.testing.expectEqual(@as(?usize, null), findCandidate("hello\n-x\nworld"));
    try std.testing.expectEqual(@as(?usize, 5), findCandidate("hello\n-"));
    try std.testing.expectEqual(@as(?usize, 5), findCandidate("hello\n"));
    try std.testing.expectEqual(@as(?usize, null), findCandidate(""));
}

test "findCandidate agrees with the scalar reference on every alignment" {
    var prng = std.Random.DefaultPrng.init(0x6d696d65);
    const random = prng.random();
    var buf: [700]u8 = undefined;
    const alphabet = "ab\n-\r";
    for (0..2000) |_| {
        const len = random.uintLessThan(usize, buf.len);
        for (buf[0..len]) |*c| c.* = alphabet[random.uintLessThan(usize, alphabet.len)];
        // Sparse variant: mostly letters, so the vector loop runs long stretches.
        if (random.boolean()) {
            for (buf[0..len]) |*c| {
                if (random.uintLessThan(u8, 16) != 0) c.* = 'a';
            }
        }
        const start = if (len == 0) 0 else random.uintLessThan(usize, len);
        try std.testing.expectEqual(findCandidateScalar(buf[start..len]), findCandidate(buf[start..len]));
    }
}

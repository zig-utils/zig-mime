//! Walker tests. Every expected transcript is checked three ways: the message fed whole, split
//! into two chunks at every possible position, and fed one byte at a time, so the event stream
//! is shown not to depend on chunking.
const std = @import("std");
const mime = @import("root.zig");

const testing = std.testing;
const Walker = mime.Walker;
const Transcript = mime.Transcript;
const Limits = mime.Limits;

pub const Options = struct {
    limits: Limits = .{},
    scratch_len: usize = 4096,
    /// Header block given to `beginWithHeaders` before feeding.
    headers: ?[]const u8 = null,
};

/// Converts the "\n" line endings of a literal to CRLF.
pub inline fn crlf(comptime s: []const u8) *const [s.len + std.mem.count(u8, s, "\n")]u8 {
    comptime {
        @setEvalBranchQuota(100_000);
        var buf: [s.len + std.mem.count(u8, s, "\n")]u8 = undefined;
        var i = 0;
        for (s) |c| {
            if (c == '\n') {
                buf[i] = '\r';
                i += 1;
            }
            buf[i] = c;
            i += 1;
        }
        const final = buf;
        return &final;
    }
}

/// Walks `input` split at the offsets in `cuts` (ascending) and returns the transcript.
pub fn walkCuts(gpa: std.mem.Allocator, input: []const u8, cuts: []const usize, opts: Options) ![]u8 {
    var t = Transcript.init(gpa);
    defer t.deinit();
    const scratch = try gpa.alloc(u8, opts.scratch_len);
    defer gpa.free(scratch);
    var w = Walker.init(scratch, t.sink(), opts.limits);
    if (opts.headers) |h| try w.beginWithHeaders(h);
    var prev: usize = 0;
    for (cuts) |c| {
        try w.feed(input[prev..c]);
        prev = c;
    }
    try w.feed(input[prev..]);
    try w.finish();
    return gpa.dupe(u8, t.text());
}

/// Walks `input` in chunks of `chunk` bytes.
pub fn walkChunked(gpa: std.mem.Allocator, input: []const u8, chunk: usize, opts: Options) ![]u8 {
    var t = Transcript.init(gpa);
    defer t.deinit();
    const scratch = try gpa.alloc(u8, opts.scratch_len);
    defer gpa.free(scratch);
    var w = Walker.init(scratch, t.sink(), opts.limits);
    if (opts.headers) |h| try w.beginWithHeaders(h);
    var i: usize = 0;
    while (i < input.len) : (i += chunk) try w.feed(input[i..@min(i + chunk, input.len)]);
    try w.finish();
    return gpa.dupe(u8, t.text());
}

pub fn expectWalk(input: []const u8, opts: Options, expected: []const u8) !void {
    const gpa = testing.allocator;
    const whole = try walkCuts(gpa, input, &.{}, opts);
    defer gpa.free(whole);
    try testing.expectEqualStrings(expected, whole);
    for (1..@max(input.len, 1)) |i| {
        const got = try walkCuts(gpa, input, &.{i}, opts);
        defer gpa.free(got);
        if (!std.mem.eql(u8, expected, got)) {
            std.debug.print("split at {d}\n", .{i});
            try testing.expectEqualStrings(expected, got);
        }
    }
    const bytewise = try walkChunked(gpa, input, 1, opts);
    defer gpa.free(bytewise);
    try testing.expectEqualStrings(expected, bytewise);
}

test "single part message" {
    try expectWalk(crlf(
        \\Subject: hi
        \\
        \\Hello
        \\World
        \\
    ), .{},
        \\begin 0: leaf text/plain
        \\body 0: content Hello\r\nWorld\r\n
        \\end 0:
        \\
    );
}

test "multipart with preamble and epilogue" {
    try expectWalk(crlf(
        \\Content-Type: multipart/mixed; boundary="b1"
        \\
        \\preamble
        \\--b1
        \\Content-Type: text/plain
        \\
        \\one
        \\--b1
        \\
        \\two
        \\--b1--
        \\epilogue
        \\
    ), .{},
        \\begin 0: multipart multipart/mixed
        \\body 0: preamble preamble
        \\begin 1:1 leaf text/plain
        \\body 1:1 content one
        \\end 1:1
        \\begin 1:2 leaf text/plain
        \\body 1:2 content two
        \\end 1:2
        \\body 0: epilogue epilogue\r\n
        \\end 0:
        \\
    );
}

test "nested multiparts and an embedded message" {
    try expectWalk(crlf(
        \\Content-Type: multipart/mixed; boundary=outer
        \\
        \\--outer
        \\Content-Type: multipart/alternative; boundary=inner
        \\
        \\--inner
        \\
        \\plain
        \\--inner
        \\Content-Type: text/html
        \\
        \\<p>html</p>
        \\--inner--
        \\--outer
        \\Content-Type: message/rfc822
        \\
        \\Subject: fwd
        \\Content-Type: multipart/mixed; boundary=deep
        \\
        \\--deep
        \\Content-Type: application/octet-stream
        \\
        \\MZ
        \\--deep--
        \\--outer--
        \\
    ), .{},
        \\begin 0: multipart multipart/mixed
        \\begin 1:1 multipart multipart/alternative
        \\begin 2:1.1 leaf text/plain
        \\body 2:1.1 content plain
        \\end 2:1.1
        \\begin 2:1.2 leaf text/html
        \\body 2:1.2 content <p>html</p>
        \\end 2:1.2
        \\end 1:1
        \\begin 1:2 message message/rfc822
        \\begin 2:2 multipart multipart/mixed
        \\begin 3:2.1 leaf application/octet-stream
        \\body 3:2.1 content MZ
        \\end 3:2.1
        \\end 2:2
        \\end 1:2
        \\end 0:
        \\
    );
}

test "bare LF line endings" {
    try expectWalk("Content-Type: multipart/mixed; boundary=b\n\n--b\nContent-Type: text/plain\n\nx\n--b--\n", .{},
        \\begin 0: multipart multipart/mixed
        \\begin 1:1 leaf text/plain
        \\body 1:1 content x
        \\end 1:1
        \\end 0:
        \\
    );
}

test "an outer delimiter closes an inner multipart; end of input closes the rest" {
    try expectWalk(crlf(
        \\Content-Type: multipart/mixed; boundary=a
        \\
        \\--a
        \\Content-Type: multipart/mixed; boundary=b
        \\
        \\--b
        \\
        \\inner
        \\--a
        \\
        \\last
    ), .{},
        \\begin 0: multipart multipart/mixed
        \\begin 1:1 multipart multipart/mixed
        \\begin 2:1.1 leaf text/plain
        \\body 2:1.1 content inner
        \\end 2:1.1
        \\diag missing_close_delimiter 1:1
        \\end 1:1
        \\begin 1:2 leaf text/plain
        \\body 1:2 content last
        \\end 1:2
        \\diag missing_close_delimiter 0:
        \\end 0:
        \\
    );
}

test "a delimiter at the end of input without a line ending" {
    try expectWalk(crlf(
        \\Content-Type: multipart/mixed; boundary=a
        \\
        \\--a
        \\
        \\x
        \\--a--
    ), .{},
        \\begin 0: multipart multipart/mixed
        \\begin 1:1 leaf text/plain
        \\body 1:1 content x
        \\end 1:1
        \\end 0:
        \\
    );
}

test "text that only resembles a delimiter stays in the body" {
    try expectWalk(crlf(
        \\Content-Type: multipart/mixed; boundary=abc
        \\
        \\--abc
        \\
        \\--ab
        \\-- signature
        \\--
        \\--abc--
        \\
    ), .{},
        \\begin 0: multipart multipart/mixed
        \\begin 1:1 leaf text/plain
        \\body 1:1 content --ab\r\n-- signature\r\n--
        \\end 1:1
        \\end 0:
        \\
    );
}

test "depth limit delivers the deep container as one leaf" {
    try expectWalk(crlf(
        \\Content-Type: multipart/mixed; boundary=a
        \\
        \\--a
        \\Content-Type: multipart/mixed; boundary=b
        \\
        \\--b
        \\
        \\deep
        \\--b--
        \\--a--
    ), .{ .limits = .{ .max_depth = 1 } },
        \\begin 0: multipart multipart/mixed
        \\begin 1:1 leaf multipart/mixed
        \\diag depth_exceeded 1:1
        \\body 1:1 content --b\r\n\r\ndeep\r\n--b--
        \\end 1:1
        \\end 0:
        \\
    );
}

test "part limit delivers the remaining parts as unparsed bytes" {
    try expectWalk(crlf(
        \\Content-Type: multipart/mixed; boundary=a
        \\
        \\--a
        \\
        \\one
        \\--a
        \\
        \\two
        \\--a--
    ), .{ .limits = .{ .max_parts = 2 } },
        \\begin 0: multipart multipart/mixed
        \\begin 1:1 leaf text/plain
        \\body 1:1 content one
        \\end 1:1
        \\diag part_limit 0:
        \\body 0: unparsed \r\ntwo
        \\end 0:
        \\
    );
}

test "oversized header blocks are reported and the walk continues" {
    try expectWalk(crlf(
        \\Content-Type: multipart/mixed; boundary=a
        \\
        \\--a
        \\X-Pad: 0123456789012345678901234567890123456789
        \\Content-Type: text/html
        \\
        \\body
        \\--a--
    ), .{ .limits = .{ .max_header_bytes = 60 } },
        \\begin 0: multipart multipart/mixed
        \\diag header_too_large 1:1
        \\begin 1:1 leaf text/plain
        \\body 1:1 content body
        \\end 1:1
        \\end 0:
        \\
    );
}

test "scratch exhaustion is reported" {
    try expectWalk(crlf(
        \\Content-Type: multipart/mixed; boundary=a
        \\X-Pad: 0123456789
        \\
        \\--a
        \\Content-Type: text/html
        \\
        \\body
        \\--a--
    ), .{ .scratch_len = 70 },
        \\begin 0: multipart multipart/mixed
        \\diag scratch_exhausted 1:1
        \\begin 1:1 leaf text/plain
        \\body 1:1 content body
        \\end 1:1
        \\end 0:
        \\
    );
}

test "a body given headers from outside the stream" {
    try expectWalk(crlf(
        \\--f
        \\Content-Disposition: form-data; name="a"
        \\
        \\1
        \\--f--
        \\
    ), .{ .headers = "Content-Type: multipart/form-data; boundary=f" },
        \\begin 0: multipart multipart/form-data
        \\begin 1:1 leaf text/plain
        \\body 1:1 content 1
        \\end 1:1
        \\end 0:
        \\
    );
}

test "empty input still yields one part" {
    try expectWalk("", .{},
        \\begin 0: leaf text/plain
        \\end 0:
        \\
    );
}

test "mbox From line is skipped" {
    try expectWalk("From someone@example.com Mon Jan  1 00:00:00 2024\nSubject: x\n\nbody", .{},
        \\begin 0: leaf text/plain
        \\body 0: content body
        \\end 0:
        \\
    );
}

/// Produces a large nested message chunk by chunk without holding it in memory.
pub const BigMessage = struct {
    body_bytes: usize,
    emitted: usize = 0,
    phase: u8 = 0,
    line: [78]u8 = undefined,

    const head = crlf(
        \\Content-Type: multipart/mixed; boundary=outer
        \\
        \\--outer
        \\Content-Type: multipart/mixed; boundary=inner
        \\
        \\--inner
        \\Content-Type: application/octet-stream
        \\
        \\
    );
    const tail = crlf(
        \\
        \\--inner--
        \\--outer--
        \\
    );

    /// Next chunk, or null at the end. The returned slice lives until the next call.
    pub fn next(self: *BigMessage) ?[]const u8 {
        switch (self.phase) {
            0 => {
                self.phase = 1;
                return head;
            },
            1 => {
                if (self.emitted >= self.body_bytes) {
                    self.phase = 2;
                    return tail;
                }
                for (self.line[0..76], 0..) |*c, i| c.* = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[(i + self.emitted) % 64];
                self.line[76] = '\r';
                self.line[77] = '\n';
                self.emitted += self.line.len;
                return &self.line;
            },
            else => return null,
        }
    }
};

const CountingSink = struct {
    parts: usize = 0,
    content: u64 = 0,
    diagnostics: usize = 0,

    pub fn onEvent(self: *CountingSink, event: mime.Event) mime.Sink.Error!void {
        switch (event) {
            .part_begin => self.parts += 1,
            .body => |b| self.content += b.bytes.len,
            .diagnostic => self.diagnostics += 1,
            .part_end => {},
        }
    }
};

test "memory stays fixed while a large nested message streams through" {
    var scratch: [4096]u8 = undefined;
    var sink: CountingSink = .{};
    var w = Walker.init(&scratch, mime.Sink.init(&sink), .{});
    var gen: BigMessage = .{ .body_bytes = 4 * 1024 * 1024 };
    while (gen.next()) |chunk| try w.feed(chunk);
    try w.finish();
    try testing.expectEqual(@as(usize, 3), sink.parts);
    try testing.expectEqual(@as(usize, 0), sink.diagnostics);
    try testing.expect(sink.content >= gen.body_bytes);
    try testing.expect(w.scratch_peak < 512);
    try testing.expect(Walker.memoryFootprint(scratch.len) < 64 * 1024);
}

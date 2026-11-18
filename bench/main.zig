//! `zig build bench -- <results.json>`: throughput of the boundary scan, the transfer decoders
//! and the walker (which decodes the base64 attachments), plus a 100 MB streaming walk that
//! checks peak memory stays fixed.
const std = @import("std");
const builtin = @import("builtin");
const bench = @import("bench");
const mime = @import("mime");

const mib = 1024 * 1024;

var message: []u8 = &.{};
var base64_lines: []u8 = &.{};
var qp_text: []u8 = &.{};
var decode_out: []u8 = &.{};
var sink_total: u64 = 0;

const CountingSink = struct {
    content: u64 = 0,
    parts: u32 = 0,
    diagnostics: u32 = 0,

    pub fn onEvent(self: *CountingSink, event: mime.Event) mime.Sink.Error!void {
        switch (event) {
            .part_begin => self.parts += 1,
            .body => |b| self.content += b.bytes.len,
            .diagnostic => self.diagnostics += 1,
            .part_end => {},
        }
    }
};

const b64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn fillBase64Lines(buf: []u8, seed: usize) void {
    var i: usize = 0;
    while (i + 78 <= buf.len) : (i += 78) {
        for (buf[i..][0..76], 0..) |*c, j| c.* = b64_alphabet[(i / 78 * 7 + j + seed) % 64];
        buf[i + 76] = '\r';
        buf[i + 77] = '\n';
    }
    @memset(buf[i..], 'A');
}

/// A nested message of roughly `size` bytes: text, an alternative pair and base64 attachments.
fn buildMessage(gpa: std.mem.Allocator, size: usize) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.appendSlice(gpa, "From: a@example.com\r\nSubject: bench\r\nContent-Type: multipart/mixed; boundary=\"=_outer_0123456789\"\r\n\r\n");
    try out.appendSlice(gpa, "--=_outer_0123456789\r\nContent-Type: multipart/alternative; boundary=\"=_alt_42\"\r\n\r\n");
    try out.appendSlice(gpa, "--=_alt_42\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello,\r\n-- \r\nsignature\r\n");
    try out.appendSlice(gpa, "--=_alt_42\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>Hello</p>\r\n--=_alt_42--\r\n");
    var n: usize = 0;
    while (out.items.len < size) : (n += 1) {
        try out.print(gpa, "--=_outer_0123456789\r\nContent-Type: application/octet-stream; name=\"f{d}.bin\"\r\n" ++
            "Content-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"f{d}.bin\"\r\n\r\n", .{ n, n });
        const start = out.items.len;
        try out.resize(gpa, start + mib);
        fillBase64Lines(out.items[start..], n);
        try out.appendSlice(gpa, "\r\n");
    }
    try out.appendSlice(gpa, "--=_outer_0123456789--\r\n");
    return out.toOwnedSlice(gpa);
}

fn benchScan() void {
    var pos: usize = 0;
    var hits: u64 = 0;
    while (mime.scan.findCandidate(base64_lines[pos..])) |c| {
        hits += 1;
        pos += c + 1;
    }
    sink_total +%= hits + pos;
}

fn benchBase64() void {
    var d: mime.decode.base64.Decoder = .{};
    var n = d.decode(base64_lines, decode_out);
    n += d.finish(decode_out[n..]);
    sink_total +%= n;
}

fn benchQp() void {
    var d: mime.decode.qp.Decoder = .{};
    var n = d.decode(qp_text, decode_out);
    n += d.finish(decode_out[n..]);
    sink_total +%= n;
}

/// Text with an escape every few words and soft breaks, like a quoted-printable HTML body.
fn fillQp(buf: []u8) void {
    const line = "<p>Caf=C3=A9 au lait, cr=C3=A8me br=C3=BBl=C3=A9e and a long run of plain words=\r\n";
    var i: usize = 0;
    while (i + line.len <= buf.len) : (i += line.len) @memcpy(buf[i..][0..line.len], line);
    @memset(buf[i..], 'x');
}

fn walkAll(data: []const u8, chunk: usize) CountingSink {
    var scratch: [16 * 1024]u8 = undefined;
    var sink: CountingSink = .{};
    var w = mime.Walker.init(&scratch, mime.Sink.init(&sink), .{});
    var i: usize = 0;
    while (i < data.len) : (i += chunk) w.feed(data[i..@min(i + chunk, data.len)]) catch unreachable;
    w.finish() catch unreachable;
    return sink;
}

fn benchWalker() void {
    sink_total +%= walkAll(message, 64 * 1024).content;
}

fn benchWalkerSmallChunks() void {
    sink_total +%= walkAll(message, 1500).content;
}

const Result = struct { name: []const u8, bytes: usize, mean_ns: f64 };

fn run(gpa: std.mem.Allocator, io: std.Io, name: []const u8, func: *const fn () void, bytes: usize) !Result {
    const b = bench.Benchmark.withOptions(name, func, .{
        .warmup_iterations = 2,
        .min_iterations = 5,
        .max_iterations = 200,
        .min_time_ns = 500_000_000,
    });
    var r = try b.run(gpa, io);
    defer r.deinit();
    const mbps = @as(f64, @floatFromInt(bytes)) / (r.mean / 1e9) / @as(f64, mib);
    std.debug.print("{s:<32} {d:>10.1} us/op {d:>10.1} MiB/s\n", .{ name, r.mean / 1000, mbps });
    return .{ .name = name, .bytes = bytes, .mean_ns = r.mean };
}

fn maxRss() usize {
    const ru = std.posix.getrusage(std.posix.rusage.SELF);
    const v: usize = @intCast(ru.maxrss);
    return if (builtin.os.tag.isDarwin()) v else v * 1024;
}

const Stress = struct { bytes: u64, rss_growth: usize, scratch_peak: usize, walker_bytes: usize };

/// Streams a 100 MB nested message through a walker from a generator, never holding it.
fn stress() !Stress {
    var scratch: [64 * 1024]u8 = undefined;
    var sink: CountingSink = .{};
    var w = mime.Walker.init(&scratch, mime.Sink.init(&sink), .{});
    var block: [64 * 1024]u8 = undefined;
    const rss_before = maxRss();
    try w.feed("Content-Type: multipart/mixed; boundary=outer\r\n\r\n--outer\r\n" ++
        "Content-Type: multipart/mixed; boundary=inner\r\n\r\n");
    var total: u64 = 0;
    var part: usize = 0;
    while (total < 100 * mib) : (part += 1) {
        try w.feed("--inner\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\n");
        for (0..16) |k| {
            fillBase64Lines(&block, part + k);
            try w.feed(&block);
            total += block.len;
        }
        try w.feed("\r\n");
    }
    try w.feed("--inner--\r\n--outer--\r\n");
    try w.finish();
    if (sink.diagnostics != 0) return error.UnexpectedDiagnostics;
    return .{
        .bytes = total,
        .rss_growth = maxRss() -| rss_before,
        .scratch_peak = w.scratch_peak,
        .walker_bytes = @sizeOf(mime.Walker),
    };
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const out_path = if (args.len > 1) args[1] else "zig-out/bench.json";
    if (std.fs.path.dirname(out_path)) |dir| try std.Io.Dir.cwd().createDirPath(io, dir);

    const st = try stress();
    std.debug.print("stress: {d} MiB streamed, rss growth {d} KiB, scratch peak {d} B, walker {d} B\n", .{
        st.bytes / mib, st.rss_growth / 1024, st.scratch_peak, st.walker_bytes,
    });
    if (st.rss_growth + st.walker_bytes > mib) return error.MemoryNotBounded;

    message = try buildMessage(gpa, 16 * mib);
    defer gpa.free(message);
    base64_lines = try gpa.alloc(u8, 4 * mib);
    defer gpa.free(base64_lines);
    fillBase64Lines(base64_lines, 0);
    qp_text = try gpa.alloc(u8, 4 * mib);
    defer gpa.free(qp_text);
    fillQp(qp_text);
    decode_out = try gpa.alloc(u8, 5 * mib);
    defer gpa.free(decode_out);

    var results: std.ArrayList(Result) = .empty;
    defer results.deinit(gpa);
    try results.append(gpa, try run(gpa, io, "scan base64 4MiB", benchScan, base64_lines.len));
    try results.append(gpa, try run(gpa, io, "base64 decode 4MiB", benchBase64, base64_lines.len));
    try results.append(gpa, try run(gpa, io, "quoted-printable decode 4MiB", benchQp, qp_text.len));
    try results.append(gpa, try run(gpa, io, "walk 16MiB chunks 64KiB", benchWalker, message.len));
    try results.append(gpa, try run(gpa, io, "walk 16MiB chunks 1500B", benchWalkerSmallChunks, message.len));
    std.mem.doNotOptimizeAway(sink_total);

    const file = try std.Io.Dir.cwd().createFile(io, out_path, .{});
    defer file.close(io);
    var buf: [4096]u8 = undefined;
    var fw = file.writer(io, &buf);
    const w = &fw.interface;
    try w.writeAll("{\n  \"benchmarks\": [\n");
    for (results.items, 0..) |r, i| {
        const mbps = @as(f64, @floatFromInt(r.bytes)) / (r.mean_ns / 1e9) / @as(f64, mib);
        try w.print("    {{\"name\": \"{s}\", \"bytes\": {d}, \"mean_ns\": {d:.0}, \"mib_per_s\": {d:.1}}}{s}\n", .{
            r.name, r.bytes, r.mean_ns, mbps, if (i + 1 < results.items.len) "," else "",
        });
    }
    try w.print("  ],\n  \"stress\": {{\"mib\": {d}, \"rss_growth_bytes\": {d}, \"scratch_peak\": {d}, \"walker_bytes\": {d}}}\n}}\n", .{
        st.bytes / mib, st.rss_growth, st.scratch_peak, st.walker_bytes,
    });
    try w.flush();
}

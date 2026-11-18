//! A sink that renders the event stream as text, one line per event, merging adjacent body
//! events of the same part and region. Raw-view bytes of a part are collected and written just
//! before its end line. The result does not depend on how the input was split into chunks,
//! which is what the tests and the fuzzer compare. It allocates, so it is a
//! debugging and testing aid, not something for the hot path.
const std = @import("std");
const walker = @import("walker.zig");

const Event = walker.Event;
const Sink = walker.Sink;

pub const Transcript = struct {
    gpa: std.mem.Allocator,
    out: std.ArrayList(u8) = .empty,
    /// Part index and region of the body line still open, if any.
    open_body: ?struct { index: u32, region: walker.Region } = null,
    /// Raw-view bytes of the current leaf.
    raw: std.ArrayList(u8) = .empty,

    pub fn init(gpa: std.mem.Allocator) Transcript {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *Transcript) void {
        self.out.deinit(self.gpa);
        self.raw.deinit(self.gpa);
    }

    pub fn sink(self: *Transcript) Sink {
        return Sink.init(self);
    }

    /// The rendered transcript; closes an open body line.
    pub fn text(self: *Transcript) []const u8 {
        self.closeBody() catch {};
        return self.out.items;
    }

    pub fn onEvent(self: *Transcript, event: Event) Sink.Error!void {
        self.record(event) catch return error.Aborted;
    }

    fn record(self: *Transcript, event: Event) !void {
        const w = self.gpa;
        switch (event) {
            .body => |b| {
                if (b.raw) return self.raw.appendSlice(w, b.bytes);
                if (self.open_body) |o| {
                    if (o.index == b.part.index and o.region == b.region) return self.escape(b.bytes);
                }
                try self.closeBody();
                try self.out.appendSlice(w, "body ");
                try self.writePath(b.part);
                try self.out.print(w, " {t} ", .{b.region});
                self.open_body = .{ .index = b.part.index, .region = b.region };
                try self.escape(b.bytes);
            },
            .part_begin => |p| {
                try self.closeBody();
                try self.out.appendSlice(w, "begin ");
                try self.writePath(p);
                try self.out.print(w, " {t} {s}/{s}", .{ p.kind, p.content_type.media_type, p.content_type.media_subtype });
                try self.out.append(w, '\n');
            },
            .part_end => |e| {
                try self.closeBody();
                if (self.raw.items.len > 0) {
                    try self.out.appendSlice(w, "raw ");
                    try self.writePath(e.part);
                    try self.out.append(w, ' ');
                    try self.escape(self.raw.items);
                    try self.out.append(w, '\n');
                    self.raw.clearRetainingCapacity();
                }
                try self.out.appendSlice(w, "end ");
                try self.writePath(e.part);
                if (e.decode_flags.any()) {
                    const f = e.decode_flags;
                    if (f.invalid_input) try self.out.appendSlice(w, " invalid_input");
                    if (f.padding_inside) try self.out.appendSlice(w, " padding_inside");
                    if (f.truncated) try self.out.appendSlice(w, " truncated");
                }
                try self.out.append(w, '\n');
            },
            .diagnostic => |d| {
                try self.closeBody();
                try self.out.print(w, "diag {t}", .{d.kind});
                if (d.part) |p| {
                    try self.out.append(w, ' ');
                    try self.writePath(p);
                }
                try self.out.append(w, '\n');
            },
        }
    }

    fn closeBody(self: *Transcript) !void {
        if (self.open_body == null) return;
        self.open_body = null;
        try self.out.append(self.gpa, '\n');
    }

    fn writePath(self: *Transcript, p: *const walker.Part) !void {
        try self.out.print(self.gpa, "{d}:", .{p.depth});
        for (p.path, 0..) |n, i| {
            if (i > 0) try self.out.append(self.gpa, '.');
            try self.out.print(self.gpa, "{d}", .{n});
        }
    }

    fn escape(self: *Transcript, bytes: []const u8) !void {
        for (bytes) |c| {
            switch (c) {
                '\r' => try self.out.appendSlice(self.gpa, "\\r"),
                '\n' => try self.out.appendSlice(self.gpa, "\\n"),
                '\\' => try self.out.appendSlice(self.gpa, "\\\\"),
                ' '...'[', ']'...'~' => try self.out.append(self.gpa, c),
                else => try self.out.print(self.gpa, "\\x{x:0>2}", .{c}),
            }
        }
    }
};

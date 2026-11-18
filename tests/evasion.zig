//! Evasion corpus: messages built the way attackers hide attachments from scanners. Every sample
//! must yield the attachment (its marker reaches the scanner in decoded content), and every
//! tolerance and limit it relies on must be reported as a diagnostic.
//!
//! The scanner here does what the Guardian engine does with the walker: it scans decoded leaf
//! bodies and the bytes of multipart regions, and walks a leaf again with a second walker when
//! the walker delivered a container as a leaf (an encoded container or the depth limit).
const std = @import("std");
const mime = @import("mime");

const marker = "ZIG-MIME-EVASION-MARKER";

const Sample = struct {
    file: []const u8,
    /// Diagnostics that must be reported.
    diags: []const mime.DiagnosticKind = &.{},
    options: mime.Options = .{},
    /// The marker may arrive as unparsed multipart bytes instead of a leaf body.
    in_unparsed: bool = false,
};

const samples = [_]Sample{
    .{ .file = "bare_lf" },
    .{ .file = "mixed_line_endings" },
    .{ .file = "missing_final_boundary", .diags = &.{.missing_close_delimiter} },
    .{ .file = "duplicate_boundary_first_decoy", .diags = &.{.conflicting_boundary} },
    .{ .file = "duplicate_boundary_last_decoy", .diags = &.{.conflicting_boundary} },
    .{ .file = "duplicate_content_type", .diags = &.{.duplicate_header} },
    .{ .file = "boundary_in_quoted_param", .diags = &.{.boundary_invalid} },
    .{ .file = "boundary_rfc2231" },
    .{ .file = "part_after_close", .diags = &.{.part_after_close} },
    .{ .file = "nested_same_boundary", .diags = &.{.nested_boundary_reuse} },
    .{ .file = "boundary_suffix", .diags = &.{.boundary_suffix} },
    .{ .file = "missing_header_separator", .diags = &.{.missing_header_separator} },
    .{ .file = "multipart_without_blank_line", .diags = &.{.missing_header_separator} },
    .{ .file = "encoded_container", .diags = &.{.encoded_container} },
    .{ .file = "rfc822_base64", .diags = &.{.encoded_container} },
    .{ .file = "deep_nesting", .diags = &.{.depth_exceeded} },
    .{ .file = "part_limit", .diags = &.{.part_limit}, .options = .{ .max_parts = 5 }, .in_unparsed = true },
    .{ .file = "header_padding", .diags = &.{.header_too_large} },
    .{ .file = "duplicate_cte", .diags = &.{.duplicate_header} },
    .{ .file = "base64_after_padding", .diags = &.{.invalid_encoding} },
    .{ .file = "base64_junk", .diags = &.{.invalid_encoding} },
    .{ .file = "qp_obfuscated" },
    .{ .file = "long_boundary", .diags = &.{.boundary_invalid} },
    .{ .file = "folded_boundary_param" },
    .{ .file = "case_and_spacing" },
    .{ .file = "filename_conflict", .diags = &.{.conflicting_filename} },
    .{ .file = "mbox_from_line" },
};

const Findings = struct {
    in_leaf: bool = false,
    in_unparsed: bool = false,
    diags: std.EnumSet(mime.DiagnosticKind) = .empty,
    filename_alt: ?[]const u8 = null,
    walks: usize = 0,
};

const Scanner = struct {
    gpa: std.mem.Allocator,
    findings: *Findings,
    options: mime.Options,
    nesting: usize,
    leaf: std.ArrayList(u8) = .empty,
    region: std.ArrayList(u8) = .empty,
    failed: ?anyerror = null,

    fn deinit(self: *Scanner) void {
        self.leaf.deinit(self.gpa);
        self.region.deinit(self.gpa);
    }

    pub fn onEvent(self: *Scanner, event: mime.Event) mime.Sink.Error!void {
        self.handle(event) catch |err| {
            self.failed = err;
            return error.Aborted;
        };
    }

    fn handle(self: *Scanner, event: mime.Event) !void {
        switch (event) {
            .part_begin => |p| {
                self.leaf.clearRetainingCapacity();
                if (p.filename_alt) |alt| {
                    if (std.mem.eql(u8, alt, "payload.exe")) self.findings.filename_alt = "payload.exe";
                }
            },
            .body => |b| switch (b.region) {
                .content => if (!b.raw) try self.leaf.appendSlice(self.gpa, b.bytes),
                else => {
                    try self.region.appendSlice(self.gpa, b.bytes);
                    if (b.region == .unparsed and std.mem.indexOf(u8, self.region.items, marker) != null) {
                        self.findings.in_unparsed = true;
                    }
                },
            },
            .part_end => |e| {
                if (e.part.kind != .leaf) return;
                if (std.mem.indexOf(u8, self.leaf.items, marker) != null) self.findings.in_leaf = true;
                const ct = e.part.content_type;
                if ((ct.isMultipart() or ct.isEmbeddedMessage()) and self.nesting < 4) {
                    const content = try self.gpa.dupe(u8, self.leaf.items);
                    defer self.gpa.free(content);
                    var header_buf: [512]u8 = undefined;
                    const header: ?[]const u8 = if (ct.isMultipart())
                        try std.fmt.bufPrint(&header_buf, "Content-Type: {s}", .{e.part.headers.get("content-type").?})
                    else
                        null;
                    try walk(self.gpa, content, header, self.options, self.findings, self.nesting + 1);
                }
            },
            .diagnostic => |d| self.findings.diags.insert(d.kind),
        }
    }
};

fn walk(gpa: std.mem.Allocator, data: []const u8, header: ?[]const u8, options: mime.Options, findings: *Findings, nesting: usize) !void {
    findings.walks += 1;
    var scanner: Scanner = .{ .gpa = gpa, .findings = findings, .options = options, .nesting = nesting };
    defer scanner.deinit();
    var scratch: [128 * 1024]u8 = undefined;
    var w = mime.Walker.init(&scratch, mime.Sink.init(&scanner), options);
    errdefer if (scanner.failed) |err| std.debug.print("scanner failed: {t}\n", .{err});
    if (header) |h| try w.beginWithHeaders(h);
    // Odd-sized chunks so delimiters straddle chunk boundaries.
    var i: usize = 0;
    while (i < data.len) : (i += 997) try w.feed(data[i..@min(i + 997, data.len)]);
    try w.finish();
}

test "every evasion sample yields the attachment and reports its tolerances" {
    const gpa = std.testing.allocator;
    var failures: usize = 0;
    inline for (samples) |s| {
        const data = @embedFile("evasion/" ++ s.file ++ ".eml");
        var findings: Findings = .{};
        try walk(gpa, data, null, s.options, &findings, 0);
        const found = if (s.in_unparsed) findings.in_unparsed else findings.in_leaf;
        if (!found) {
            std.debug.print("{s}: attachment not delivered\n", .{s.file});
            failures += 1;
        }
        for (s.diags) |d| {
            if (!findings.diags.contains(d)) {
                std.debug.print("{s}: diagnostic {t} not reported\n", .{ s.file, d });
                failures += 1;
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 0), failures);
}

test "conflicting filenames expose both" {
    var findings: Findings = .{};
    try walk(std.testing.allocator, @embedFile("evasion/filename_conflict.eml"), null, .{}, &findings, 0);
    try std.testing.expectEqualStrings("payload.exe", findings.filename_alt.?);
}

test "a clean walk reports nothing" {
    var findings: Findings = .{};
    try walk(std.testing.allocator, @embedFile("evasion/bare_lf.eml"), null, .{}, &findings, 0);
    try std.testing.expect(findings.in_leaf);
    try std.testing.expect(findings.diags.count() == 0);
}

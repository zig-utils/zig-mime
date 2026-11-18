//! The streaming MIME walker: a push parser over a message, fed in chunks of any size.
//!
//! Memory is fixed: the walker struct itself (about 20 KiB, no heap) plus a caller-provided
//! scratch buffer that holds the header blocks of the parts currently open. Headers of a
//! container stay in scratch until the container ends, so every `Part` handed to the sink stays
//! valid until its `part_end` event. Body bytes are never buffered: content events point into
//! the chunk being fed, apart from at most one line start (a possible delimiter, at most
//! `max_boundary_len + 4` bytes) carried across a chunk boundary.
//!
//! Delimiter lines are found with a SIMD search for "\n--" (see scan.zig) and then verified
//! against the boundary of every open multipart, innermost first. A boundary of an outer
//! multipart closes inner parts that never saw their own close delimiter, as RFC 2046 implies and
//! mail clients do.
const std = @import("std");
const headers = @import("headers.zig");
const scan = @import("scan.zig");
const decode = @import("decode.zig");
const text = @import("text.zig");

const Headers = headers.Headers;
const ContentType = headers.ContentType;

/// Deepest nesting the walker can track; `Options.max_depth` is clamped to it.
pub const max_depth_cap = 32;
/// Longest boundary the walker will split on. RFC 2046 allows 70; longer ones occur in the wild
/// and are accepted with a `boundary_invalid` diagnostic up to this length.
pub const max_boundary_len = 256;
/// Bytes of a line start needed to decide whether it is a delimiter line.
const head_cap = 2 + max_boundary_len + 2;

pub const Options = struct {
    /// Deepest part depth (the top-level message is depth 0). A container that would nest its
    /// children deeper is reported with `depth_exceeded` and delivered as one opaque leaf.
    max_depth: u8 = 16,
    /// Most parts (part_begin events) per message. Past it, `part_limit` is reported and the rest
    /// of each multipart is delivered as `unparsed` body bytes of that multipart.
    max_parts: u32 = 10_000,
    /// Most raw header bytes stored for one part. Lines past it are reported with
    /// `header_too_large` and not stored; the walk continues.
    max_header_bytes: u32 = 64 * 1024,
    /// Also deliver the undecoded body of base64 and quoted-printable parts, as `body` events
    /// with `raw` set, before the decoded bytes. Lets a scanner check both views of a part
    /// whose encoding is broken or lies.
    raw_view: bool = false,
};

pub const Kind = enum {
    /// A part with a body: decoded content arrives as `body` events.
    leaf,
    /// A multipart: its children follow, and its preamble and epilogue arrive as `body` events.
    multipart,
    /// message/rfc822 or message/global: the embedded message follows as one child.
    message,
};

pub const Part = struct {
    /// Ordinal of this part in the message, from 0 for the top-level entity.
    index: u32 = 0,
    /// Nesting depth: 0 for the top-level entity, parent depth + 1 for every child.
    depth: u8 = 0,
    /// IMAP-style section path: a multipart's children append their 1-based index, while the
    /// message embedded in a message/rfc822 part shares that part's path. The top-level entity
    /// has an empty path.
    path: []const u32 = &.{},
    kind: Kind = .leaf,
    headers: Headers = .{},
    content_type: ContentType = .default,
    /// The boundary this multipart splits on (also when `kind` fell back to leaf).
    boundary: ?[]const u8 = null,
    /// Content-Transfer-Encoding. A leaf's `body` events carry decoded bytes.
    encoding: decode.Encoding = .none,
    /// The Content-Type charset parameter, as written.
    charset: ?[]const u8 = null,
    disposition: headers.Disposition.Kind = .none,
    /// Content-Disposition filename, decoded to UTF-8 (RFC 2231 sections and charsets first,
    /// then RFC 2047 encoded words in a plain value).
    filename: ?[]const u8 = null,
    /// Content-Type name parameter, decoded the same way.
    name: ?[]const u8 = null,
};

pub const Region = enum {
    /// Body of a leaf.
    content,
    /// Bytes of a multipart before its first delimiter.
    preamble,
    /// Bytes of a multipart after its close delimiter.
    epilogue,
    /// Bytes of a multipart that were not split into parts because a limit was reached.
    unparsed,
};

pub const Body = struct {
    part: *const Part,
    bytes: []const u8,
    region: Region,
    /// The bytes are the undecoded body of an encoded part (only with `Options.raw_view`).
    raw: bool = false,
};

pub const PartEnd = struct {
    part: *const Part,
    /// Body bytes of this part as they appeared in the message, before transfer decoding.
    raw_bytes: u64,
    /// Bytes delivered as decoded content.
    decoded_bytes: u64,
    /// What the transfer decoder tolerated.
    decode_flags: decode.Flags,
};

pub const DiagnosticKind = enum {
    /// A part's header block exceeded `Options.max_header_bytes`; later lines were not stored.
    header_too_large,
    /// The scratch buffer ran out while storing a header block; later lines were not stored.
    scratch_exhausted,
    /// A header line is longer than the 998 characters RFC 5322 allows.
    header_line_too_long,
    /// A line that is not a header field ended the header block without a blank line; it was
    /// treated as the first body line.
    missing_header_separator,
    /// The Content-Type value has no type/subtype; the RFC 2045 default was used.
    invalid_content_type,
    /// A multipart has no usable boundary parameter; it was delivered as a leaf.
    multipart_without_boundary,
    /// A boundary is longer than `max_boundary_len`; the multipart was delivered as a leaf.
    boundary_too_long,
    /// A boundary fails the mail server's RFC 2046 validation (over 70 characters or outside
    /// the bchars set). The walker still splits on it, as mail clients do.
    boundary_invalid,
    /// A decoded filename or name parameter did not fit (scratch or the 2 KiB parameter cap)
    /// and was cut short.
    parameter_truncated,
    /// A delimiter line continues past the boundary with something other than "--" and
    /// whitespace. It still counts as a delimiter, as in mail clients that match the prefix.
    boundary_suffix,
    /// A multipart ended (outer delimiter or end of input) without its close delimiter.
    missing_close_delimiter,
    /// The nesting limit stopped the walker from descending into a container.
    depth_exceeded,
    /// The part limit was reached; the rest of the multipart is delivered as unparsed bytes.
    part_limit,
    /// The Content-Transfer-Encoding is not one this library decodes; the body is passed on as
    /// it is.
    unknown_transfer_encoding,
    /// A multipart or message part declares base64 or quoted-printable, which RFC 2045 forbids.
    /// It is delivered as a decoded leaf; walk its content with a second walker to see inside.
    encoded_container,
    /// The transfer decoder met invalid input or data after base64 padding (see
    /// `PartEnd.decode_flags`); it kept going.
    invalid_encoding,
};

pub const Diagnostic = struct {
    kind: DiagnosticKind,
    /// The part the diagnostic is about; valid until that part's `part_end`.
    part: ?*const Part,
    /// Approximate stream offset where it was detected.
    offset: u64,
};

pub const Event = union(enum) {
    part_begin: *const Part,
    body: Body,
    part_end: PartEnd,
    diagnostic: Diagnostic,
};

/// Where the walker sends its events. Return `error.Aborted` to stop the walk; the walker must
/// not be fed again afterwards.
pub const Sink = struct {
    context: *anyopaque,
    onEventFn: *const fn (context: *anyopaque, event: Event) Error!void,

    pub const Error = error{Aborted};

    /// A sink calling `pointer.onEvent(event)`.
    pub fn init(pointer: anytype) Sink {
        const T = @typeInfo(@TypeOf(pointer)).pointer.child;
        const gen = struct {
            fn call(context: *anyopaque, event: Event) Error!void {
                const self: *T = @ptrCast(@alignCast(context));
                return self.onEvent(event);
            }
        };
        return .{ .context = pointer, .onEventFn = gen.call };
    }
};

/// Diagnostics found while parsing a header block, emitted right after its part_begin.
const Pending = struct {
    kinds: [8]DiagnosticKind = undefined,
    len: usize = 0,

    fn add(self: *Pending, kind: DiagnosticKind) void {
        if (self.len == self.kinds.len) return;
        self.kinds[self.len] = kind;
        self.len += 1;
    }
};

const MultipartState = enum { preamble, open, closed, overflow };

const Entity = struct {
    part: Part = .{},
    /// Scratch top before this entity's headers; restored when it ends.
    mark: usize = 0,
    path_len: u8 = 0,
    mp: MultipartState = .preamble,
    children: u32 = 0,
    raw_bytes: u64 = 0,
    decoded_bytes: u64 = 0,
    decoder: decode.Decoder = .identity,
};

const State = enum { start, header, header_rest, skip_line, body, done };
const AfterSkip = enum { new_part, header, body };

const Delim = struct {
    /// Stack index of the multipart the delimiter belongs to.
    level: u8,
    close: bool,
    exact: bool,
    /// Bytes from the line start through the boundary (and its "--" for a close delimiter).
    len: usize,
};

const DelimClass = union(enum) { not, need_more, delim: Delim };
const HeaderLine = union(enum) { need_more, blank, field, continuation, other, mbox_from, delim: Delim };

pub const Walker = struct {
    sink: Sink,
    scratch: []u8,
    options: Options,

    /// Stream bytes consumed so far.
    offset: u64 = 0,
    /// Parts begun so far.
    parts: u32 = 0,
    /// Highest scratch use so far, in bytes.
    scratch_peak: usize = 0,

    stack: [max_depth_cap + 1]Entity = undefined,
    len: u8 = 0,
    path: [max_depth_cap + 1]u32 = undefined,
    state: State = .start,
    after_skip: AfterSkip = .body,
    skip_garbage: bool = false,
    scratch_top: usize = 0,

    // Header block being collected.
    hdr_start: usize = 0,
    hdr_len: usize = 0,
    hdr_overflow: bool = false,
    line_start: usize = 0,
    line_len: usize = 0,
    line_stored: bool = false,
    long_line_reported: bool = false,
    first_line: bool = false,

    /// Start of the current line while it is being classified (header lines and possible
    /// delimiter lines in bodies).
    head: [head_cap]u8 = undefined,
    head_len: usize = 0,

    // Body scanner.
    /// Line ending that precedes a possible delimiter; it belongs to the delimiter if one follows.
    eol: [2]u8 = undefined,
    eol_len: u8 = 0,
    cr_pending: bool = false,
    at_line_start: bool = false,

    /// Staging buffer for decoded body bytes.
    out: [4096]u8 = undefined,

    pub fn init(scratch: []u8, sink: Sink, options: Options) Walker {
        var l = options;
        l.max_depth = @min(l.max_depth, max_depth_cap);
        return .{ .sink = sink, .scratch = scratch, .options = l };
    }

    /// Starts the walk at the body of an entity whose header block (`raw_headers`, lines ending
    /// in CRLF or LF) is known from outside the stream, such as an HTTP request's Content-Type.
    /// Call before the first `feed`. Without it the stream starts with the message headers.
    pub fn beginWithHeaders(self: *Walker, raw_headers: []const u8) Sink.Error!void {
        std.debug.assert(self.state == .start);
        self.pushChild();
        self.beginHeaders();
        self.long_line_reported = true; // several lines arrive as one; per-line length is unknown
        try self.startStoredLine(raw_headers);
        if (raw_headers.len > 0 and raw_headers[raw_headers.len - 1] != '\n') try self.appendStoredLine("\n");
        try self.endHeaders();
    }

    /// Walks the next chunk of the message.
    pub fn feed(self: *Walker, data: []const u8) Sink.Error!void {
        std.debug.assert(self.state != .done);
        var rest = data;
        while (rest.len > 0) {
            const n = try self.step(rest);
            rest = rest[n..];
            self.offset += n;
        }
    }

    /// Ends the message: flushes held bytes and closes every open part, reporting multiparts
    /// that never saw their close delimiter.
    pub fn finish(self: *Walker) Sink.Error!void {
        while (true) {
            switch (self.state) {
                .start => try self.beginTop(),
                .header => if (self.head_len > 0) try self.resolveHeaderLineAtEof() else try self.endHeaders(),
                .header_rest => self.finishLine(),
                .skip_line => self.afterSkip(),
                .body => if (!try self.flushBodyAtEof()) break,
                .done => break,
            }
        }
        while (self.len > 0) try self.endTop();
        self.state = .done;
    }

    /// Bytes of fixed memory a walker uses with a scratch buffer of `scratch_len` bytes.
    pub fn memoryFootprint(scratch_len: usize) usize {
        return @sizeOf(Walker) + scratch_len;
    }

    // Stepping

    /// Consumes a prefix of `data` (possibly empty when only the state changes).
    fn step(self: *Walker, data: []const u8) Sink.Error!usize {
        switch (self.state) {
            .start => {
                try self.beginTop();
                return 0;
            },
            .header => return self.stepHeader(data),
            .header_rest => return self.stepHeaderRest(data),
            .skip_line => return self.stepSkip(data),
            .body => return self.stepBody(data),
            .done => unreachable,
        }
    }

    /// Re-runs held bytes through the state machine.
    fn replay(self: *Walker, data: []const u8) Sink.Error!void {
        var rest = data;
        while (rest.len > 0) rest = rest[try self.step(rest)..];
    }

    fn beginTop(self: *Walker) Sink.Error!void {
        self.pushChild();
        self.beginHeaders();
        self.first_line = true;
    }

    fn top(self: *Walker) *Entity {
        return &self.stack[self.len - 1];
    }

    fn pushChild(self: *Walker) void {
        const d = self.len;
        const e = &self.stack[d];
        e.* = .{ .mark = self.scratch_top };
        if (d > 0) {
            const parent = &self.stack[d - 1];
            if (parent.part.kind == .multipart) {
                e.path_len = parent.path_len + 1;
                self.path[e.path_len - 1] = parent.children;
            } else {
                e.path_len = parent.path_len;
            }
        }
        e.part.depth = d;
        e.part.path = self.path[0..e.path_len];
        e.part.index = self.parts;
        self.parts += 1;
        self.len += 1;
    }

    fn endTop(self: *Walker) Sink.Error!void {
        const e = self.top();
        if (e.part.kind == .multipart and e.mp != .closed) try self.diag(.missing_close_delimiter, &e.part);
        if (e.part.kind == .leaf) {
            try e.decoder.finish(&self.out, DecodedSink{ .walker = self, .entity = e });
            const f = e.decoder.flags();
            if (f.invalid_input or f.padding_inside) try self.diag(.invalid_encoding, &e.part);
        }
        try self.emit(.{ .part_end = .{
            .part = &e.part,
            .raw_bytes = e.raw_bytes,
            .decoded_bytes = e.decoded_bytes,
            .decode_flags = e.decoder.flags(),
        } });
        self.scratch_top = e.mark;
        self.len -= 1;
    }

    // Headers

    fn beginHeaders(self: *Walker) void {
        self.hdr_start = self.scratch_top;
        self.hdr_len = 0;
        self.hdr_overflow = false;
        self.line_stored = false;
        self.long_line_reported = false;
        self.head_len = 0;
        self.state = .header;
    }

    fn stepHeader(self: *Walker, data: []const u8) Sink.Error!usize {
        var k = @min(head_cap - self.head_len, data.len);
        var complete = false;
        if (std.mem.indexOfScalar(u8, data[0..k], '\n')) |nl| {
            k = nl + 1;
            complete = true;
        }
        @memcpy(self.head[self.head_len..][0..k], data[0..k]);
        self.head_len += k;
        const class = self.classifyHeaderLine(self.head[0..self.head_len], complete);
        if (class == .need_more) return k;
        var line: [head_cap]u8 = undefined;
        const n = self.head_len;
        @memcpy(line[0..n], self.head[0..n]);
        self.head_len = 0;
        try self.applyHeaderLine(class, line[0..n], complete);
        return k;
    }

    fn applyHeaderLine(self: *Walker, class: HeaderLine, line: []const u8, complete: bool) Sink.Error!void {
        const was_first = self.first_line;
        self.first_line = false;
        switch (class) {
            .need_more => unreachable,
            .blank => try self.endHeaders(),
            .field, .continuation => {
                try self.startStoredLine(line);
                if (complete) self.finishLine() else self.state = .header_rest;
            },
            .mbox_from => {
                std.debug.assert(was_first);
                if (!complete) {
                    self.state = .skip_line;
                    self.after_skip = .header;
                    self.skip_garbage = true;
                }
            },
            .delim => |d| {
                try self.endHeaders();
                try self.handleDelimiter(d);
                try self.replay(line[@min(d.len, line.len)..]);
            },
            .other => {
                try self.diag(.missing_header_separator, &self.top().part);
                try self.endHeaders();
                try self.replay(line);
            },
        }
    }

    fn resolveHeaderLineAtEof(self: *Walker) Sink.Error!void {
        var line: [head_cap]u8 = undefined;
        const n = self.head_len;
        @memcpy(line[0..n], self.head[0..n]);
        self.head_len = 0;
        const class = self.classifyHeaderLine(line[0..n], true);
        switch (class) {
            .delim => |d| {
                self.first_line = false;
                try self.endHeaders();
                try self.handleDelimiter(d);
            },
            .field, .continuation => {
                self.first_line = false;
                try self.startStoredLine(line[0..n]);
                self.finishLine();
            },
            else => try self.applyHeaderLine(class, line[0..n], true),
        }
    }

    fn stepHeaderRest(self: *Walker, data: []const u8) Sink.Error!usize {
        const nl = std.mem.indexOfScalar(u8, data, '\n');
        const seg = data[0..if (nl) |i| i + 1 else data.len];
        try self.appendStoredLine(seg);
        if (nl != null) self.finishLine();
        return seg.len;
    }

    fn finishLine(self: *Walker) void {
        self.state = .header;
        self.head_len = 0;
    }

    fn startStoredLine(self: *Walker, bytes: []const u8) Sink.Error!void {
        self.line_start = self.hdr_len;
        self.line_len = 0;
        self.line_stored = !self.hdr_overflow;
        try self.appendStoredLine(bytes);
    }

    fn appendStoredLine(self: *Walker, bytes: []const u8) Sink.Error!void {
        self.line_len += bytes.len;
        if (self.line_len > 998 + 2 and !self.long_line_reported) {
            self.long_line_reported = true;
            try self.diag(.header_line_too_long, &self.top().part);
        }
        if (!self.line_stored) return;
        const by_scratch = self.scratch.len - self.hdr_start;
        const cap = @min(self.options.max_header_bytes, by_scratch);
        if (self.hdr_len + bytes.len <= cap) {
            @memcpy(self.scratch[self.hdr_start + self.hdr_len ..][0..bytes.len], bytes);
            self.hdr_len += bytes.len;
            self.notePeak(self.hdr_start + self.hdr_len);
            return;
        }
        self.hdr_len = self.line_start;
        self.line_stored = false;
        if (!self.hdr_overflow) {
            self.hdr_overflow = true;
            const kind: DiagnosticKind = if (by_scratch < self.options.max_header_bytes) .scratch_exhausted else .header_too_large;
            try self.diag(kind, &self.top().part);
        }
    }

    fn notePeak(self: *Walker, used: usize) void {
        self.scratch_peak = @max(self.scratch_peak, used);
    }

    fn classifyHeaderLine(self: *Walker, line: []const u8, complete: bool) HeaderLine {
        if (line.len == 0) return if (complete) .blank else .need_more;
        switch (line[0]) {
            '\n' => return .blank,
            '\r' => {
                if (line.len == 1) return if (complete) .blank else .need_more;
                return if (line[1] == '\n') .blank else .other;
            },
            '-' => switch (self.classifyDelimiter(line, complete)) {
                .need_more => return .need_more,
                .delim => |d| return .{ .delim = d },
                .not => {},
            },
            ' ', '\t' => return .continuation,
            else => {},
        }
        if (self.first_line and self.len == 1) {
            const from = "From ";
            if (line.len < from.len and !complete and std.mem.startsWith(u8, from, line)) return .need_more;
            if (std.mem.startsWith(u8, line, from)) return .mbox_from;
        }
        const full = line.len == head_cap;
        var i: usize = 0;
        while (i < line.len and headers.isNameChar(line[i])) : (i += 1) {}
        if (i == line.len) return if (complete) .other else if (full) .field else .need_more;
        if (i == 0) return .other;
        while (i < line.len and (line[i] == ' ' or line[i] == '\t')) : (i += 1) {}
        if (i == line.len) return if (complete or full) .other else .need_more;
        return if (line[i] == ':') .field else .other;
    }

    fn endHeaders(self: *Walker) Sink.Error!void {
        const e = self.top();
        const block = headers.unfold(self.scratch[self.hdr_start..][0..self.hdr_len]);
        self.scratch_top = self.hdr_start + block.len;
        e.part.headers = .{ .block = block };

        var pending: Pending = .{};

        const in_digest = self.len >= 2 and self.stack[self.len - 2].part.kind == .multipart and
            self.stack[self.len - 2].part.content_type.is("multipart", "digest");
        var ct: ContentType = if (in_digest) .digest_default else .default;
        if (e.part.headers.get("content-type")) |value| {
            if (ContentType.parse(value)) |parsed| {
                ct = parsed;
            } else |_| pending.add(.invalid_content_type);
        }
        e.part.content_type = ct;
        e.part.charset = ct.charset;

        var kind: Kind = .leaf;
        if (ct.isMultipart()) {
            e.part.boundary = self.boundaryOf(ct);
            const b = e.part.boundary orelse "";
            if (b.len == 0) {
                pending.add(.multipart_without_boundary);
            } else if (b.len > max_boundary_len) {
                pending.add(.boundary_too_long);
            } else {
                headers.validateBoundary(b) catch pending.add(.boundary_invalid);
                if (e.part.depth + 1 > self.options.max_depth) pending.add(.depth_exceeded) else kind = .multipart;
            }
        } else if (ct.isEmbeddedMessage()) {
            if (e.part.depth + 1 > self.options.max_depth) pending.add(.depth_exceeded) else kind = .message;
        }
        var encoding: decode.Encoding = .none;
        if (e.part.headers.get("content-transfer-encoding")) |value| {
            encoding = decode.Encoding.parse(value);
            if (encoding == .unknown) pending.add(.unknown_transfer_encoding);
        }
        if (kind != .leaf and !encoding.isIdentity()) {
            pending.add(.encoded_container);
            kind = .leaf;
        }
        e.part.encoding = encoding;
        e.part.kind = kind;
        if (kind == .leaf) e.decoder = .init(encoding);

        var disposition_params: []const u8 = "";
        if (e.part.headers.get("content-disposition")) |value| {
            const d = headers.Disposition.parse(value);
            e.part.disposition = d.kind;
            disposition_params = d.params;
        }
        e.part.filename = self.decodeParam(disposition_params, "filename", &pending);
        e.part.name = self.decodeParam(ct.params, "name", &pending);

        try self.emit(.{ .part_begin = &e.part });
        for (pending.kinds[0..pending.len]) |k| try self.diag(k, &e.part);

        switch (kind) {
            .multipart => {
                e.mp = .preamble;
                self.enterBody();
            },
            .message => {
                self.pushChild();
                self.beginHeaders();
            },
            .leaf => self.enterBody(),
        }
    }

    /// The boundary parameter with quoted-string escapes removed (into scratch when it has any).
    fn boundaryOf(self: *Walker, ct: ContentType) ?[]const u8 {
        const p = headers.findParam(ct.params, "boundary") orelse return null;
        if (!p.quoted or std.mem.indexOfScalar(u8, p.value, '\\') == null) return p.value;
        const room = self.scratch[self.scratch_top..];
        if (room.len < p.value.len) return p.value;
        const b = headers.unquote(p.value, room);
        self.bump(b.len);
        return b;
    }

    /// Decodes a filename-like parameter (RFC 2231, RFC 2047) into scratch.
    fn decodeParam(self: *Walker, params: []const u8, name: []const u8, pending: *Pending) ?[]const u8 {
        const r = text.decodeParam(params, name, self.scratch[self.scratch_top..]) orelse return null;
        self.bump(r.text.len);
        if (r.flags.truncated) pending.add(.parameter_truncated);
        return r.text;
    }

    fn bump(self: *Walker, n: usize) void {
        self.scratch_top += n;
        self.notePeak(self.scratch_top);
    }

    // Delimiters

    fn classifyDelimiter(self: *Walker, bytes: []const u8, eof: bool) DelimClass {
        var line = bytes;
        var complete = eof;
        if (std.mem.indexOfScalar(u8, bytes, '\n')) |nl| {
            line = bytes[0..nl];
            complete = true;
        }
        if (line.len == 0) return if (complete) .not else .need_more;
        if (line[0] != '-') return .not;
        if (line.len < 2) return if (complete) .not else .need_more;
        if (line[1] != '-') return .not;

        var best: ?Delim = null;
        var best_rank: u8 = 255;
        var i: usize = self.len;
        while (i > 0) {
            i -= 1;
            const e = &self.stack[i];
            if (e.part.kind != .multipart) continue;
            const b = e.part.boundary.?;
            const m = matchBoundary(line, b, complete);
            const rank: u8 = switch (m) {
                .undecided => return .need_more,
                .no => continue,
                .exact => if (e.mp == .closed) 1 else 0,
                .prefix => if (e.mp == .closed) 3 else 2,
            };
            if (rank < best_rank) {
                best_rank = rank;
                const close = switch (m) {
                    .exact, .prefix => |c| c,
                    else => unreachable,
                };
                best = .{
                    .level = @intCast(i),
                    .close = close,
                    .exact = m == .exact,
                    .len = 2 + b.len + @as(usize, if (close) 2 else 0),
                };
            }
        }
        return if (best) |d| .{ .delim = d } else .not;
    }

    const Match = union(enum) { undecided, no, exact: bool, prefix: bool };

    /// Matches the line (without its line ending) against "--" ++ boundary. `exact` means the
    /// boundary is followed by "--", whitespace or the end of the line; `prefix` means something
    /// else follows. The payload says whether it is a close delimiter.
    fn matchBoundary(line: []const u8, b: []const u8, complete: bool) Match {
        const need = 2 + b.len;
        const n = @min(line.len, need);
        if (!std.mem.eql(u8, line[2..n], b[0 .. n - 2])) return .no;
        if (line.len < need) return if (complete) .no else .undecided;
        const r = line[need..];
        if (r.len == 0) return if (complete) .{ .exact = false } else .undecided;
        switch (r[0]) {
            '-' => {
                if (r.len == 1) return if (complete) .{ .prefix = false } else .undecided;
                return if (r[1] == '-') .{ .exact = true } else .{ .prefix = false };
            },
            ' ', '\t', '\r' => return .{ .exact = false },
            else => return .{ .prefix = false },
        }
    }

    fn handleDelimiter(self: *Walker, d: Delim) Sink.Error!void {
        while (self.len - 1 > d.level) try self.endTop();
        const f = &self.stack[d.level];
        self.skip_garbage = !d.exact;
        if (!d.exact) try self.diag(.boundary_suffix, &f.part);
        self.state = .skip_line;
        self.after_skip = .body;
        if (d.close) {
            f.mp = .closed;
            return;
        }
        if (f.mp == .overflow) return;
        if (self.parts >= self.options.max_parts) {
            f.mp = .overflow;
            try self.diag(.part_limit, &f.part);
            return;
        }
        f.mp = .open;
        f.children += 1;
        self.pushChild();
        self.after_skip = .new_part;
    }

    fn stepSkip(self: *Walker, data: []const u8) Sink.Error!usize {
        const nl = std.mem.indexOfScalar(u8, data, '\n');
        const seg = data[0..if (nl) |i| i + 1 else data.len];
        if (!self.skip_garbage) {
            for (seg) |c| {
                if (c != ' ' and c != '\t' and c != '\r' and c != '\n') {
                    self.skip_garbage = true;
                    try self.diag(.boundary_suffix, &self.top().part);
                    break;
                }
            }
        }
        if (nl != null) self.afterSkip();
        return seg.len;
    }

    fn afterSkip(self: *Walker) void {
        switch (self.after_skip) {
            .new_part => self.beginHeaders(),
            .header => self.finishLine(),
            .body => self.enterBody(),
        }
    }

    // Bodies

    fn enterBody(self: *Walker) void {
        self.state = .body;
        self.at_line_start = true;
        self.eol_len = 0;
        self.cr_pending = false;
        self.head_len = 0;
    }

    fn stepBody(self: *Walker, data: []const u8) Sink.Error!usize {
        if (self.cr_pending) {
            self.cr_pending = false;
            if (data[0] == '\n') {
                self.eol = "\r\n".*;
                self.eol_len = 2;
                self.at_line_start = true;
                return 1;
            }
            try self.content("\r");
            return 0;
        }
        if (self.at_line_start) return self.stepLineStart(data);
        if (scan.findCandidate(data)) |c| {
            var end = c;
            if (end > 0 and data[end - 1] == '\r') end -= 1;
            try self.content(data[0..end]);
            const eol = data[end .. c + 1];
            @memcpy(self.eol[0..eol.len], eol);
            self.eol_len = @intCast(eol.len);
            self.at_line_start = true;
            return c + 1;
        }
        var end = data.len;
        if (data[end - 1] == '\r') {
            end -= 1;
            self.cr_pending = true;
        }
        try self.content(data[0..end]);
        return data.len;
    }

    fn stepLineStart(self: *Walker, data: []const u8) Sink.Error!usize {
        const old = self.head_len;
        if (old == 0) {
            switch (self.classifyDelimiter(data, false)) {
                .not => {
                    self.at_line_start = false;
                    try self.flushEol();
                    return 0;
                },
                .delim => |d| {
                    self.at_line_start = false;
                    self.eol_len = 0;
                    try self.handleDelimiter(d);
                    return d.len;
                },
                .need_more => {
                    @memcpy(self.head[0..data.len], data);
                    self.head_len = data.len;
                    return data.len;
                },
            }
        }
        const k = @min(head_cap - old, data.len);
        @memcpy(self.head[old..][0..k], data[0..k]);
        switch (self.classifyDelimiter(self.head[0 .. old + k], false)) {
            .not => {
                self.head_len = 0;
                self.at_line_start = false;
                try self.flushEol();
                try self.content(self.head[0..old]);
                return 0;
            },
            .delim => |d| {
                self.head_len = 0;
                self.at_line_start = false;
                self.eol_len = 0;
                try self.handleDelimiter(d);
                return @max(d.len, old) - old;
            },
            .need_more => {
                self.head_len = old + k;
                return k;
            },
        }
    }

    /// Flushes held body bytes at the end of input. Returns true when a delimiter changed the
    /// state and `finish` has to keep going.
    fn flushBodyAtEof(self: *Walker) Sink.Error!bool {
        if (self.cr_pending) {
            self.cr_pending = false;
            try self.content("\r");
        }
        if (self.at_line_start and self.head_len > 0) {
            const n = self.head_len;
            self.head_len = 0;
            self.at_line_start = false;
            switch (self.classifyDelimiter(self.head[0..n], true)) {
                .delim => |d| {
                    self.eol_len = 0;
                    try self.handleDelimiter(d);
                    return true;
                },
                .not => {
                    try self.flushEol();
                    try self.content(self.head[0..n]);
                },
                .need_more => unreachable,
            }
        }
        try self.flushEol();
        return false;
    }

    fn flushEol(self: *Walker) Sink.Error!void {
        const n = self.eol_len;
        if (n == 0) return;
        self.eol_len = 0;
        try self.content(self.eol[0..n]);
    }

    fn content(self: *Walker, bytes: []const u8) Sink.Error!void {
        if (bytes.len == 0) return;
        const e = self.top();
        e.raw_bytes += bytes.len;
        switch (e.part.kind) {
            .leaf, .message => {
                if (self.options.raw_view and e.decoder != .identity) {
                    try self.emit(.{ .body = .{ .part = &e.part, .bytes = bytes, .region = .content, .raw = true } });
                }
                try e.decoder.feed(bytes, &self.out, DecodedSink{ .walker = self, .entity = e });
            },
            .multipart => {
                const region: Region = switch (e.mp) {
                    .preamble => .preamble,
                    .closed => .epilogue,
                    .open, .overflow => .unparsed,
                };
                try self.emit(.{ .body = .{ .part = &e.part, .bytes = bytes, .region = region } });
            },
        }
    }

    /// Receives decoded bytes from an entity's transfer decoder.
    const DecodedSink = struct {
        walker: *Walker,
        entity: *Entity,

        pub fn write(self: DecodedSink, bytes: []const u8) Sink.Error!void {
            self.entity.decoded_bytes += bytes.len;
            try self.walker.emit(.{ .body = .{ .part = &self.entity.part, .bytes = bytes, .region = .content } });
        }
    };

    // Events

    fn emit(self: *Walker, event: Event) Sink.Error!void {
        try self.sink.onEventFn(self.sink.context, event);
    }

    fn diag(self: *Walker, kind: DiagnosticKind, part: ?*const Part) Sink.Error!void {
        try self.emit(.{ .diagnostic = .{ .kind = kind, .part = part, .offset = self.offset } });
    }
};

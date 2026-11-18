//! `zig build bench -- <results.json>`: kernel micro-benchmarks with zig-bench. The end-to-end
//! parser benchmarks land with P2.11.
const std = @import("std");
const bench = @import("bench");

var sink: u64 = 0;

fn baseline() void {
    sink +%= 1;
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const out_path = if (args.len > 1) args[1] else "zig-out/bench.json";
    if (std.fs.path.dirname(out_path)) |dir| try std.Io.Dir.cwd().createDirPath(init.io, dir);
    var suite = bench.BenchmarkSuite.init(init.gpa, init.io);
    defer suite.deinit();
    try suite.add("baseline", baseline);
    suite.setBaseline(out_path);
    try suite.run();
    std.mem.doNotOptimizeAway(sink);
}

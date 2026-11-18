//! Deterministic fuzzing: `zig build fuzz -Dfuzz-iterations=N -Dfuzz-seed=S`.
const std = @import("std");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const iterations = if (args.len > 1) try std.fmt.parseInt(usize, args[1], 10) else 10_000;
    const seed = if (args.len > 2) try std.fmt.parseInt(u64, args[2], 10) else 0x5eed_5eed;
    std.debug.print("fuzz: {d} cases, seed {d}, no targets yet\n", .{ iterations, seed });
}

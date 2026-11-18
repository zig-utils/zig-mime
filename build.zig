const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mime = b.addModule("mime", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    }) })).step);

    const fuzz_exe = b.addExecutable(.{
        .name = "fuzz",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/fuzz.zig"),
            .target = target,
            .optimize = if (optimize == .debug) .safe else optimize,
            .imports = &.{.{ .name = "mime", .module = mime }},
        }),
    });
    const run_fuzz = b.addRunArtifact(fuzz_exe);
    const fuzz_iterations = b.option(usize, "fuzz-iterations", "Deterministic fuzz case count") orelse 10_000;
    const fuzz_seed = b.option(u64, "fuzz-seed", "Deterministic fuzz seed") orelse 0x5eed_5eed;
    run_fuzz.addArgs(&.{ b.fmt("{d}", .{fuzz_iterations}), b.fmt("{d}", .{fuzz_seed}) });
    b.step("fuzz", "Run deterministic fuzz cases").dependOn(&run_fuzz.step);

    const bench_step = b.step("bench", "Run benchmarks and write a JSON result file");
    if (b.lazyDependency("bench", .{ .target = target, .optimize = .fast })) |bench_dep| {
        const bench_exe = b.addExecutable(.{
            .name = "bench",
            .root_module = b.createModule(.{
                .root_source_file = b.path("bench/main.zig"),
                .target = target,
                .optimize = .fast,
                .imports = &.{
                    .{ .name = "mime", .module = mime },
                    .{ .name = "bench", .module = bench_dep.module("bench") },
                },
            }),
        });
        const run_bench = b.addRunArtifact(bench_exe);
        run_bench.addPassthruArgs();
        bench_step.dependOn(&run_bench.step);
    }
}

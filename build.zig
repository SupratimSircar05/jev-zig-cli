const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const core = b.addModule("jevx", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const jevx = b.addExecutable(.{
        .name = "jevx",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "jevx", .module = core }},
        }),
    });
    b.installArtifact(jevx);

    const decide = b.addExecutable(.{
        .name = "jev-decide",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/jev_decide_main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    // Zig 0.16.0 can deadlock two cold cross-target compiler servers that
    // share one build cache. Preserve deterministic release builds by making
    // the two independent executable compilations explicit and sequential.
    decide.step.dependOn(&jevx.step);
    b.installArtifact(decide);

    const run_step = b.step("run", "Run jevx");
    const run_cmd = b.addRunArtifact(jevx);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    run_step.dependOn(&run_cmd.step);

    const core_tests = b.addTest(.{ .root_module = core });
    const run_core_tests = b.addRunArtifact(core_tests);
    const main_tests = b.addTest(.{ .root_module = jevx.root_module });
    const run_main_tests = b.addRunArtifact(main_tests);
    const decide_tests = b.addTest(.{ .root_module = decide.root_module });
    const run_decide_tests = b.addRunArtifact(decide_tests);
    const corpus_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("policy/corpus_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "jevx", .module = core }},
        }),
    });
    const run_corpus_tests = b.addRunArtifact(corpus_tests);

    const fake_codex = b.addExecutable(.{
        .name = "fake-codex",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/fake_codex.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const stream_redaction_integration = b.addExecutable(.{
        .name = "stream-redaction-integration",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/stream_redaction_integration.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "jevx", .module = core }},
        }),
    });
    const run_stream_redaction_integration = b.addRunArtifact(stream_redaction_integration);
    run_stream_redaction_integration.addArtifactArg(fake_codex);

    const test_step = b.step("test", "Run unit, contract, and integration tests");
    test_step.dependOn(&run_core_tests.step);
    test_step.dependOn(&run_main_tests.step);
    test_step.dependOn(&run_decide_tests.step);
    test_step.dependOn(&run_corpus_tests.step);
    test_step.dependOn(&run_stream_redaction_integration.step);

    const check_step = b.step("check", "Compile both executables without installing");
    check_step.dependOn(&jevx.step);
    check_step.dependOn(&decide.step);
}

const std = @import("std");
const builtin = @import("builtin");

pub const journal_name = "audit.journal";

pub const Paths = struct {
    allocator: std.mem.Allocator,
    state_dir: []u8,
    journal: []u8,

    pub fn deinit(self: *Paths) void {
        self.allocator.free(self.state_dir);
        self.allocator.free(self.journal);
        self.* = undefined;
    }

    pub fn ensure(self: Paths, io: std.Io) !void {
        try std.Io.Dir.cwd().createDirPath(io, self.state_dir);
    }
};

pub fn resolve(allocator: std.mem.Allocator, environ: *const std.process.Environ.Map) !Paths {
    const state_dir = if (environ.get("JEVX_STATE_DIR")) |explicit|
        try requireAbsoluteCopy(allocator, explicit)
    else switch (builtin.os.tag) {
        .macos => try homeJoin(allocator, environ, &.{ "Library", "Application Support", "jevx" }),
        .linux => if (environ.get("XDG_STATE_HOME")) |xdg|
            try joinAbsolute(allocator, xdg, &.{"jevx"})
        else
            try homeJoin(allocator, environ, &.{ ".local", "state", "jevx" }),
        .windows => if (environ.get("LOCALAPPDATA")) |base|
            try joinAbsolute(allocator, base, &.{"jevx"})
        else
            return error.StateDirectoryUnavailable,
        else => try homeJoin(allocator, environ, &.{ ".local", "state", "jevx" }),
    };
    errdefer allocator.free(state_dir);
    return .{
        .allocator = allocator,
        .state_dir = state_dir,
        .journal = try std.fs.path.join(allocator, &.{ state_dir, journal_name }),
    };
}

fn homeJoin(
    allocator: std.mem.Allocator,
    environ: *const std.process.Environ.Map,
    rest: []const []const u8,
) ![]u8 {
    const home = environ.get("HOME") orelse return error.StateDirectoryUnavailable;
    return joinAbsolute(allocator, home, rest);
}

fn joinAbsolute(allocator: std.mem.Allocator, base: []const u8, rest: []const []const u8) ![]u8 {
    if (!std.fs.path.isAbsolute(base)) return error.StateDirectoryMustBeAbsolute;
    var components: std.ArrayList([]const u8) = .empty;
    defer components.deinit(allocator);
    try components.append(allocator, base);
    try components.appendSlice(allocator, rest);
    return std.fs.path.join(allocator, components.items);
}

fn requireAbsoluteCopy(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    if (value.len == 0 or !std.fs.path.isAbsolute(value)) return error.StateDirectoryMustBeAbsolute;
    return allocator.dupe(u8, value);
}

test "explicit state directory must be absolute" {
    var env = std.process.Environ.Map.init(std.testing.allocator);
    defer env.deinit();
    try env.put("JEVX_STATE_DIR", "relative");
    try std.testing.expectError(error.StateDirectoryMustBeAbsolute, resolve(std.testing.allocator, &env));
}

test "explicit state directory controls journal location" {
    var env = std.process.Environ.Map.init(std.testing.allocator);
    defer env.deinit();
    const state_dir = if (builtin.os.tag == .windows) "C:\\tmp\\jevx-test-state" else "/tmp/jevx-test-state";
    const expected = if (builtin.os.tag == .windows) "C:\\tmp\\jevx-test-state\\audit.journal" else "/tmp/jevx-test-state/audit.journal";
    try env.put("JEVX_STATE_DIR", state_dir);
    var paths = try resolve(std.testing.allocator, &env);
    defer paths.deinit();
    try std.testing.expectEqualStrings(expected, paths.journal);
}

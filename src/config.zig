const std = @import("std");
const cli = @import("cli.zig");
const policy = @import("policy.zig");

pub const Source = enum { default, user, project, environment, command_line };

pub const Value = struct {
    backend: cli.Backend = .exec,
    backend_source: Source = .default,
    policy_name: cli.PolicyName = .aggressive,
    policy_source: Source = .default,
    model: ?[]const u8 = null,
    model_source: Source = .default,
    codex_bin: []const u8 = "codex",
    jev_bin: []const u8 = "jev-decide",
};

pub const Layer = struct {
    backend: ?cli.Backend = null,
    policy_name: ?cli.PolicyName = null,
    model: ?[]const u8 = null,
    codex_bin: ?[]const u8 = null,
    jev_bin: ?[]const u8 = null,
};

pub fn parseLayerLeaky(allocator: std.mem.Allocator, bytes: []const u8) !Layer {
    if (bytes.len > 64 * 1024) return error.ConfigTooLarge;
    const parsed = try std.json.parseFromSliceLeaky(std.json.Value, allocator, bytes, .{
        .duplicate_field_behavior = .@"error",
    });
    if (parsed != .object) return error.InvalidConfig;
    const object = parsed.object;
    var layer: Layer = .{};
    if (object.get("backend")) |value| layer.backend = try parseEnumValue(cli.Backend, value);
    if (object.get("policy")) |value| layer.policy_name = try parseEnumValue(cli.PolicyName, value);
    if (object.get("model")) |value| layer.model = try nonemptyString(value);
    if (object.get("codex_bin")) |value| layer.codex_bin = try nonemptyString(value);
    if (object.get("jev_bin")) |value| layer.jev_bin = try nonemptyString(value);
    return layer;
}

pub fn environmentLayer(environ: *const std.process.Environ.Map) !Layer {
    var layer: Layer = .{};
    if (environ.get("JEVX_BACKEND")) |value| layer.backend = parseEnumText(cli.Backend, value) orelse return error.InvalidEnvironment;
    if (environ.get("JEVX_POLICY")) |value| layer.policy_name = parseEnumText(cli.PolicyName, value) orelse return error.InvalidEnvironment;
    if (environ.get("JEVX_MODEL")) |value| layer.model = value;
    if (environ.get("JEVX_CODEX_BIN")) |value| layer.codex_bin = value;
    if (environ.get("JEVX_DECIDE_BIN")) |value| layer.jev_bin = value;
    return layer;
}

pub fn commandLineLayer(options: cli.Options) Layer {
    return .{
        .backend = if (options.backend_set) options.backend else null,
        .policy_name = if (options.policy_set) options.policy else null,
        .model = options.model,
        .codex_bin = options.codex_bin,
        .jev_bin = options.jev_bin,
    };
}

fn nonemptyString(value: std.json.Value) ![]const u8 {
    if (value != .string or value.string.len == 0) return error.InvalidConfig;
    return value.string;
}

fn parseEnumValue(comptime T: type, value: std.json.Value) !T {
    const text = try nonemptyString(value);
    return parseEnumText(T, text) orelse error.InvalidConfig;
}

fn parseEnumText(comptime T: type, text: []const u8) ?T {
    inline for (@typeInfo(T).@"enum".fields) |field| {
        if (std.mem.eql(u8, text, field.name)) return @enumFromInt(field.value);
        if (comptime std.mem.indexOfScalar(u8, field.name, '_') != null) {
            var normalized: [field.name.len]u8 = undefined;
            inline for (field.name, 0..) |byte, index| normalized[index] = if (byte == '_') '-' else byte;
            if (std.mem.eql(u8, text, &normalized)) return @enumFromInt(field.value);
        }
    }
    return null;
}

/// Merge ordinary values by precedence while enforcing the special rule that a
/// project policy may tighten a user policy but never relax it.
pub fn resolve(user: Layer, project: Layer, environment: Layer, command_line: Layer) Value {
    var out: Value = .{};
    apply(&out, user, .user, false);
    if (project.policy_name) |p| {
        out.policy_name = policy.tighten(out.policy_name, p);
        if (out.policy_name == p) out.policy_source = .project;
    }
    // A repository is untrusted input. It can tighten policy, but cannot select
    // a binary, backend, or model that would execute under the user's identity.
    apply(&out, environment, .environment, false);
    apply(&out, command_line, .command_line, true);
    return out;
}

fn apply(out: *Value, layer: Layer, source: Source, command_line_layer: bool) void {
    if (layer.backend) |v| {
        out.backend = v;
        out.backend_source = source;
    }
    if (layer.policy_name) |v| {
        // Even CLI flags cannot weaken the already-resolved user/project floor.
        const tightened = policy.tighten(out.policy_name, v);
        if (tightened == v) {
            out.policy_name = v;
            out.policy_source = source;
        } else if (!command_line_layer) {
            out.policy_name = tightened;
        }
    }
    if (layer.model) |v| {
        out.model = v;
        out.model_source = source;
    }
    if (layer.codex_bin) |v| out.codex_bin = v;
    if (layer.jev_bin) |v| out.jev_bin = v;
}

test "config precedence and immutable policy floor" {
    const resolved = resolve(
        .{ .policy_name = .balanced, .model = "user-model" },
        .{ .policy_name = .conservative },
        .{ .model = "env-model" },
        .{ .policy_name = .aggressive, .model = "cli-model" },
    );
    try std.testing.expectEqual(cli.PolicyName.conservative, resolved.policy_name);
    try std.testing.expectEqualStrings("cli-model", resolved.model.?);
}

test "JSON config rejects duplicate fields" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.DuplicateField, parseLayerLeaky(arena.allocator(), "{\"policy\":\"balanced\",\"policy\":\"aggressive\"}"));
}

test "project configuration cannot select executable backend or model" {
    const resolved = resolve(
        .{ .backend = .exec, .model = "user-model", .codex_bin = "/trusted/codex", .jev_bin = "/trusted/jev-decide" },
        .{ .backend = .app_server, .model = "repo-model", .codex_bin = "/repo/payload", .jev_bin = "/repo/payload" },
        .{},
        .{},
    );
    try std.testing.expectEqual(cli.Backend.exec, resolved.backend);
    try std.testing.expectEqualStrings("user-model", resolved.model.?);
    try std.testing.expectEqualStrings("/trusted/codex", resolved.codex_bin);
    try std.testing.expectEqualStrings("/trusted/jev-decide", resolved.jev_bin);
}

fn configAllocationFailureCase(allocator: std.mem.Allocator) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    _ = try parseLayerLeaky(arena.allocator(), "{\"backend\":\"exec\",\"policy\":\"balanced\",\"model\":\"m\"}");
}

test "configuration parsing is allocation-failure safe" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, configAllocationFailureCase, .{});
}

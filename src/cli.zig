const std = @import("std");

pub const Backend = enum { exec, app_server };
pub const PolicyName = enum { aggressive, balanced, conservative };
pub const AuditAction = enum { show, verify, export_, purge };

pub const Command = union(enum) {
    repl,
    run,
    resume_: []const u8,
    decide,
    web,
    doctor,
    policy_explain,
    audit: AuditAction,
    setup,
    version,
    help,
};

pub const Options = struct {
    backend: Backend = .exec,
    backend_set: bool = false,
    policy: PolicyName = .aggressive,
    policy_set: bool = false,
    model: ?[]const u8 = null,
    json: bool = false,
    workspace: ?[]const u8 = null,
    codex_bin: ?[]const u8 = null,
    jev_bin: ?[]const u8 = null,
    prompt_file: ?[]const u8 = null,
    yes: bool = false,
};

pub const Invocation = struct {
    command: Command = .repl,
    options: Options = .{},
};

pub const ParseError = error{
    UnknownCommand,
    UnknownOption,
    MissingValue,
    MissingResumeId,
    MissingAuditAction,
    UnexpectedArgument,
};

pub fn parse(args: []const []const u8) ParseError!Invocation {
    var result: Invocation = .{};
    var saw_command = false;
    var i: usize = 1;

    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--backend")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            result.options.backend = parseEnum(Backend, args[i]) orelse return error.UnknownOption;
            result.options.backend_set = true;
        } else if (std.mem.eql(u8, arg, "--policy")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            result.options.policy = parseEnum(PolicyName, args[i]) orelse return error.UnknownOption;
            result.options.policy_set = true;
        } else if (std.mem.eql(u8, arg, "--model")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            result.options.model = args[i];
        } else if (std.mem.eql(u8, arg, "--json")) {
            result.options.json = true;
        } else if (std.mem.eql(u8, arg, "-C")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            result.options.workspace = args[i];
        } else if (std.mem.eql(u8, arg, "--codex-bin")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            result.options.codex_bin = args[i];
        } else if (std.mem.eql(u8, arg, "--jev-bin")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            result.options.jev_bin = args[i];
        } else if (std.mem.eql(u8, arg, "--prompt-file")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            result.options.prompt_file = args[i];
        } else if (std.mem.eql(u8, arg, "--yes")) {
            result.options.yes = true;
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            if (saw_command) return error.UnexpectedArgument;
            result.command = .help;
            saw_command = true;
        } else if (std.mem.startsWith(u8, arg, "-")) {
            return error.UnknownOption;
        } else if (!saw_command) {
            saw_command = true;
            if (std.mem.eql(u8, arg, "run")) {
                result.command = .run;
            } else if (std.mem.eql(u8, arg, "resume")) {
                i += 1;
                if (i >= args.len or std.mem.startsWith(u8, args[i], "-")) return error.MissingResumeId;
                result.command = .{ .resume_ = args[i] };
            } else if (std.mem.eql(u8, arg, "decide")) {
                result.command = .decide;
            } else if (std.mem.eql(u8, arg, "web")) {
                result.command = .web;
            } else if (std.mem.eql(u8, arg, "doctor")) {
                result.command = .doctor;
            } else if (std.mem.eql(u8, arg, "setup")) {
                result.command = .setup;
            } else if (std.mem.eql(u8, arg, "version")) {
                result.command = .version;
            } else if (std.mem.eql(u8, arg, "policy")) {
                i += 1;
                if (i >= args.len or !std.mem.eql(u8, args[i], "explain")) return error.UnknownCommand;
                result.command = .policy_explain;
            } else if (std.mem.eql(u8, arg, "audit")) {
                i += 1;
                if (i >= args.len) return error.MissingAuditAction;
                const action = args[i];
                result.command = .{ .audit = if (std.mem.eql(u8, action, "show"))
                    .show
                else if (std.mem.eql(u8, action, "verify"))
                    .verify
                else if (std.mem.eql(u8, action, "export"))
                    .export_
                else if (std.mem.eql(u8, action, "purge"))
                    .purge
                else
                    return error.UnknownCommand };
            } else {
                return error.UnknownCommand;
            }
        } else {
            return error.UnexpectedArgument;
        }
    }
    return result;
}

fn parseEnum(comptime T: type, text: []const u8) ?T {
    inline for (@typeInfo(T).@"enum".fields) |field| {
        const cli_name = comptime blk: {
            var result: [field.name.len]u8 = undefined;
            for (field.name, 0..) |c, j| result[j] = if (c == '_') '-' else c;
            break :blk result;
        };
        if (std.mem.eql(u8, text, &cli_name)) return @enumFromInt(field.value);
    }
    return null;
}

test "parses run with common flags in any order" {
    const invocation = try parse(&.{ "jevx", "--json", "run", "--backend", "app-server", "-C", "/tmp/repo" });
    try std.testing.expect(invocation.command == .run);
    try std.testing.expect(invocation.options.json);
    try std.testing.expectEqual(Backend.app_server, invocation.options.backend);
    try std.testing.expectEqualStrings("/tmp/repo", invocation.options.workspace.?);
}

test "does not accept a prompt as a positional argv value" {
    try std.testing.expectError(error.UnexpectedArgument, parse(&.{ "jevx", "run", "secret prompt" }));
}

test "parses audit actions" {
    const invocation = try parse(&.{ "jevx", "audit", "verify" });
    try std.testing.expectEqual(AuditAction.verify, invocation.command.audit);
}

test "parses local browser bridge" {
    const invocation = try parse(&.{ "jevx", "web", "--policy", "conservative" });
    try std.testing.expect(invocation.command == .web);
    try std.testing.expectEqual(PolicyName.conservative, invocation.options.policy);
}

//! Stable `codex exec --json` backend.
//!
//! This module intentionally exposes no arbitrary-argument escape hatch. The
//! prompt is always `-` on the command line and its bytes are written through
//! stdin by `process_runner`.

const std = @import("std");
const process_runner = @import("process_runner.zig");

pub const Sandbox = enum {
    read_only,
    workspace_write,

    pub fn cliValue(self: Sandbox) []const u8 {
        return switch (self) {
            .read_only => "read-only",
            .workspace_write => "workspace-write",
        };
    }
};

/// Sticky execution facts. Callers retain this value even when `execute`
/// returns an error, so fallback decisions cannot accidentally replay work.
pub const ActivityState = struct {
    turn_started: bool = false,
    command_started: bool = false,
    file_action_started: bool = false,

    pub fn anyActionStarted(self: ActivityState) bool {
        return self.command_started or self.file_action_started;
    }

    /// A second backend is safe only before Codex has acknowledged a turn or
    /// reported any command/file activity.
    pub fn mayFallback(self: ActivityState) bool {
        return !self.turn_started and !self.anyActionStarted();
    }
};

pub const Request = struct {
    codex_path: []const u8 = "codex",
    cwd: std.process.Child.Cwd = .inherit,
    /// Parent/source environment; `process_runner` passes only its safe
    /// allowlist to Codex. Null produces an empty environment.
    environ_map: ?*const std.process.Environ.Map = null,
    prompt: []const u8,
    resume_thread_id: ?[]const u8 = null,
    model: ?[]const u8 = null,
    sandbox: Sandbox = .read_only,
    limits: process_runner.Limits = .{},
};

pub const Result = struct {
    process: process_runner.Result,
    thread_id: ?[]u8,
    state: ActivityState,

    pub fn deinit(self: *Result, allocator: std.mem.Allocator) void {
        self.process.deinit(allocator);
        if (self.thread_id) |id| allocator.free(id);
        self.* = undefined;
    }

    pub fn succeeded(self: Result) bool {
        return self.process.succeeded();
    }
};

pub const BackendError = error{
    InvalidExecutable,
    InvalidThreadId,
    InvalidModel,
    ConflictingThreadId,
};

pub const Argv = struct {
    storage: [48][]const u8 = undefined,
    len: usize = 0,

    pub fn slice(self: *const Argv) []const []const u8 {
        return self.storage[0..self.len];
    }
};

/// Produces the complete, closed set of supported argv values. Neither the
/// prompt nor credentials can enter the returned array.
pub fn buildArgv(request: Request) BackendError!Argv {
    if (request.codex_path.len == 0 or std.mem.indexOfScalar(u8, request.codex_path, 0) != null)
        return error.InvalidExecutable;

    if (request.model) |model| try validateModel(model);

    var result: Argv = .{};
    result.storage[result.len] = request.codex_path;
    result.len += 1;
    result.storage[result.len] = "--ask-for-approval";
    result.len += 1;
    // The pinned Codex CLI exposes only `on-request` and `never` here. Jevx
    // performs its own durable preflight policy gate, so non-interactive
    // execution uses `never` inside the selected Codex sandbox. This is not
    // the dangerous sandbox-bypass mode.
    result.storage[result.len] = "never";
    result.len += 1;
    // Keep the sandbox at global scope. `codex exec resume` does not accept a
    // subcommand-local --sandbox option, while the global option applies to
    // both fresh and resumed turns.
    result.storage[result.len] = "--sandbox";
    result.len += 1;
    result.storage[result.len] = request.sandbox.cliValue();
    result.len += 1;
    result.storage[result.len] = "exec";
    result.len += 1;
    if (request.resume_thread_id) |thread_id| {
        try validateThreadId(thread_id);
        result.storage[result.len] = "resume";
        result.len += 1;
    }
    // These are immutable safety overrides. User configuration and project
    // execpolicy files are untrusted in an autonomous runner, while Codex's
    // own authentication remains available through CODEX_HOME. Tool
    // subprocesses receive neither HOME nor CODEX_HOME, and workspace-write
    // networking is disabled even after a semantic policy confirmation.
    const fixed_options = [_][]const u8{
        "--ignore-user-config",
        "--ignore-rules",
        "--strict-config",
        "-c",
        "web_search=\"disabled\"",
        "-c",
        "sandbox_workspace_write.network_access=false",
        "-c",
        "shell_environment_policy.inherit=\"none\"",
        "-c",
        "mcp_servers={}",
        "-c",
        "project_doc_max_bytes=0",
        "-c",
        "features.apps=false",
        "-c",
        "features.plugins=false",
        "-c",
        "features.hooks=false",
        "-c",
        "features.skill_search=false",
        "-c",
        "features.browser_use=false",
        "-c",
        "features.browser_use_external=false",
        "-c",
        "features.computer_use=false",
        "-c",
        "features.image_generation=false",
        "-c",
        "features.multi_agent=false",
        "-c",
        "features.multi_agent_v2=false",
        "-c",
        "features.recommended_plugins=false",
    };
    for (fixed_options) |option| {
        result.storage[result.len] = option;
        result.len += 1;
    }
    result.storage[result.len] = "--json";
    result.len += 1;
    if (request.model) |model| {
        result.storage[result.len] = "--model";
        result.len += 1;
        result.storage[result.len] = model;
        result.len += 1;
    }
    if (request.resume_thread_id) |thread_id| {
        result.storage[result.len] = "--";
        result.len += 1;
        result.storage[result.len] = thread_id;
        result.len += 1;
    }
    result.storage[result.len] = "-";
    result.len += 1;
    return result;
}

/// Executes one Codex turn. `state` is updated before forwarding each event,
/// and survives all error returns.
pub fn execute(
    allocator: std.mem.Allocator,
    io: std.Io,
    request: Request,
    state: *ActivityState,
    sink: process_runner.EventSink,
) anyerror!Result {
    var argv = try buildArgv(request);
    var tracker = try Tracker.init(allocator, state, request.resume_thread_id, sink);
    defer tracker.deinit();

    var process_result = try process_runner.run(allocator, io, .{
        .argv = argv.slice(),
        .cwd = request.cwd,
        .environ_map = request.environ_map,
        .stdin_data = request.prompt,
        .limits = request.limits,
        .sink = tracker.sink(),
    });
    errdefer process_result.deinit(allocator);

    const thread_id = tracker.thread_id;
    tracker.thread_id = null;
    return .{
        .process = process_result,
        .thread_id = thread_id,
        .state = state.*,
    };
}

fn validateThreadId(thread_id: []const u8) BackendError!void {
    if (thread_id.len == 0 or thread_id.len > 512 or !std.unicode.utf8ValidateSlice(thread_id))
        return error.InvalidThreadId;
    for (thread_id) |byte| {
        if (byte == 0 or byte == '\n' or byte == '\r' or byte < 0x20 or byte == 0x7f)
            return error.InvalidThreadId;
    }
}

fn validateModel(model: []const u8) BackendError!void {
    if (model.len == 0 or model.len > 256 or model[0] == '-' or !std.unicode.utf8ValidateSlice(model))
        return error.InvalidModel;
    for (model) |byte| {
        if (byte == 0 or byte == '\n' or byte == '\r' or byte < 0x20 or byte == 0x7f)
            return error.InvalidModel;
    }
}

const Tracker = struct {
    allocator: std.mem.Allocator,
    state: *ActivityState,
    thread_id: ?[]u8 = null,
    downstream: process_runner.EventSink,

    fn init(
        allocator: std.mem.Allocator,
        state: *ActivityState,
        initial_thread_id: ?[]const u8,
        downstream: process_runner.EventSink,
    ) !Tracker {
        return .{
            .allocator = allocator,
            .state = state,
            .thread_id = if (initial_thread_id) |id| try allocator.dupe(u8, id) else null,
            .downstream = downstream,
        };
    }

    fn deinit(self: *Tracker) void {
        if (self.thread_id) |id| self.allocator.free(id);
        self.* = undefined;
    }

    fn sink(self: *Tracker) process_runner.EventSink {
        return .{ .context = self, .on_event = receive };
    }

    fn receive(context: ?*anyopaque, event: process_runner.Event) !void {
        const self: *Tracker = @ptrCast(@alignCast(context.?));
        try self.observe(event.value.*);
        try self.downstream.emit(event);
    }

    fn observe(self: *Tracker, value: std.json.Value) !void {
        if (value != .object) return;
        const event_type = stringField(value.object, "type") orelse return;

        if (std.mem.eql(u8, event_type, "thread.started")) {
            if (threadIdFrom(value.object)) |id| try self.rememberThreadId(id);
            return;
        }
        if (std.mem.eql(u8, event_type, "turn.started")) {
            self.state.turn_started = true;
            return;
        }

        if (!std.mem.startsWith(u8, event_type, "item.")) return;
        const item_value = value.object.get("item") orelse return;
        if (item_value != .object) return;
        const item_type = stringField(item_value.object, "type") orelse return;
        if (std.mem.eql(u8, item_type, "command_execution") or
            std.mem.eql(u8, item_type, "commandExecution"))
        {
            self.state.command_started = true;
        } else if (std.mem.eql(u8, item_type, "file_change") or
            std.mem.eql(u8, item_type, "fileChange") or
            std.mem.eql(u8, item_type, "apply_patch"))
        {
            self.state.file_action_started = true;
        }
    }

    fn rememberThreadId(self: *Tracker, id: []const u8) !void {
        try validateThreadId(id);
        if (self.thread_id) |existing| {
            if (!std.mem.eql(u8, existing, id)) return error.ConflictingThreadId;
            return;
        }
        self.thread_id = try self.allocator.dupe(u8, id);
    }
};

fn threadIdFrom(object: std.json.ObjectMap) ?[]const u8 {
    if (stringField(object, "thread_id")) |id| return id;
    if (stringField(object, "threadId")) |id| return id;
    if (object.get("thread")) |thread| {
        if (thread == .object) {
            if (stringField(thread.object, "id")) |id| return id;
            if (stringField(thread.object, "thread_id")) |id| return id;
        }
    }
    return null;
}

fn stringField(object: std.json.ObjectMap, name: []const u8) ?[]const u8 {
    const value = object.get(name) orelse return null;
    return if (value == .string) value.string else null;
}

fn observeJson(tracker: *Tracker, json: []const u8) !void {
    var parsed = try process_runner.parseStrict(std.testing.allocator, json);
    defer parsed.deinit();
    try tracker.observe(parsed.value);
}

test "exec argv is closed safe and never contains the prompt" {
    const prompt = "do not leak this prompt or token sk-secret";
    var request: Request = .{ .prompt = prompt, .sandbox = .workspace_write, .model = "gpt-5.6-codex" };
    var argv = try buildArgv(request);
    try std.testing.expectEqualStrings("codex", argv.slice()[0]);
    try std.testing.expectEqualStrings("--ask-for-approval", argv.slice()[1]);
    try std.testing.expectEqualStrings("never", argv.slice()[2]);
    try std.testing.expectEqualStrings("--sandbox", argv.slice()[3]);
    try std.testing.expectEqualStrings("workspace-write", argv.slice()[4]);
    try std.testing.expectEqualStrings("exec", argv.slice()[5]);
    try std.testing.expect(argvContains(argv.slice(), "mcp_servers={}"));
    try std.testing.expect(argvContains(argv.slice(), "project_doc_max_bytes=0"));
    try std.testing.expect(argvContains(argv.slice(), "features.browser_use=false"));
    try std.testing.expect(argvContains(argv.slice(), "workspace-write"));
    for (argv.slice()) |arg| try std.testing.expect(std.mem.indexOf(u8, arg, prompt) == null);

    request.resume_thread_id = "0199-safe-thread";
    request.sandbox = .read_only;
    argv = try buildArgv(request);
    try std.testing.expectEqualStrings("read-only", argv.slice()[4]);
    try std.testing.expectEqualStrings("resume", argv.slice()[6]);
    try std.testing.expect(argvContains(argv.slice(), "read-only"));
    try std.testing.expect(argvContains(argv.slice(), "0199-safe-thread"));
    for (argv.slice()) |arg| try std.testing.expect(std.mem.indexOf(u8, arg, prompt) == null);
}

fn argvContains(argv: []const []const u8, needle: []const u8) bool {
    for (argv) |argument| if (std.mem.eql(u8, argument, needle)) return true;
    return false;
}

test "thread ids survive unknown fields and conflicting ids fail closed" {
    var state: ActivityState = .{};
    var tracker = try Tracker.init(std.testing.allocator, &state, null, .{});
    defer tracker.deinit();

    try observeJson(&tracker, "{\"type\":\"future.event\",\"unknown\":true}");
    try observeJson(&tracker, "{\"type\":\"thread.started\",\"thread_id\":\"thread-a\",\"future\":1}");
    try std.testing.expectEqualStrings("thread-a", tracker.thread_id.?);
    try observeJson(&tracker, "{\"type\":\"thread.started\",\"thread_id\":\"thread-a\"}");
    try std.testing.expectError(
        error.ConflictingThreadId,
        observeJson(&tracker, "{\"type\":\"thread.started\",\"thread_id\":\"thread-b\"}"),
    );
}

test "activity is sticky and prevents replay after a turn or action" {
    var state: ActivityState = .{};
    var tracker = try Tracker.init(std.testing.allocator, &state, null, .{});
    defer tracker.deinit();
    try std.testing.expect(state.mayFallback());

    try observeJson(&tracker, "{\"type\":\"turn.started\",\"extra\":42}");
    try std.testing.expect(!state.mayFallback());
    try observeJson(&tracker, "{\"type\":\"item.started\",\"item\":{\"id\":\"1\",\"type\":\"command_execution\"}}");
    try observeJson(&tracker, "{\"type\":\"item.completed\",\"item\":{\"id\":\"2\",\"type\":\"file_change\"}}");
    try std.testing.expect(state.command_started);
    try std.testing.expect(state.file_action_started);
}

test "unsafe thread identifiers are rejected" {
    try std.testing.expectError(error.InvalidThreadId, validateThreadId(""));
    try std.testing.expectError(error.InvalidThreadId, validateThreadId("ok\n--danger"));
    try std.testing.expectError(error.InvalidThreadId, validateThreadId(&.{0xff}));
    try std.testing.expectError(error.InvalidModel, validateModel("--danger"));
    try std.testing.expectError(error.InvalidModel, validateModel("bad\nmodel"));
}

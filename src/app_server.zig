//! Preview Codex app-server stdio backend.
//!
//! The wire transport is newline-delimited JSON-RPC without a `jsonrpc`
//! member, matching Codex app-server. The prompt travels only inside a
//! `turn/start` message over stdin and is never placed in process argv.

const std = @import("std");
const builtin = @import("builtin");
const process_runner = @import("process_runner.zig");
const codex_exec = @import("codex_exec.zig");

pub const Sandbox = codex_exec.Sandbox;
pub const ActivityState = codex_exec.ActivityState;
pub const EventSink = process_runner.EventSink;

pub const ApprovalKind = enum {
    command,
    file_change,
    permissions,
    legacy_command,
    legacy_patch,
    unsupported_request,
};

pub const ApprovalDecision = enum { accept, decline, cancel };

pub const ApprovalRequest = struct {
    kind: ApprovalKind,
    method: []const u8,
    id: *const std.json.Value,
    params: ?*const std.json.Value,
};

pub const ApprovalHandler = struct {
    context: ?*anyopaque = null,
    decide: ?*const fn (context: ?*anyopaque, request: ApprovalRequest) anyerror!ApprovalDecision = null,

    fn decision(self: ApprovalHandler, request: ApprovalRequest) !ApprovalDecision {
        if (self.decide) |callback| return callback(self.context, request);
        return .decline;
    }
};

pub const CapabilityProbe = struct {
    supported: bool = false,
    image_generation: bool = false,
    namespace_tools: bool = false,
    web_search: bool = false,
};

pub const Request = struct {
    codex_path: []const u8 = "codex",
    /// Applied both as the child cwd and as the thread's cwd. Null inherits.
    cwd: ?[]const u8 = null,
    /// Parent/source environment. A safe allowlisted copy is passed to the
    /// child; null is an empty environment and never implicit inheritance.
    environ_map: ?*const std.process.Environ.Map = null,
    prompt: []const u8,
    resume_thread_id: ?[]const u8 = null,
    model: ?[]const u8 = null,
    sandbox: Sandbox = .read_only,
    client_name: []const u8 = "jev-zig-cli",
    client_title: []const u8 = "Jev Zig CLI",
    client_version: []const u8 = "0.1.0",
    limits: process_runner.Limits = .{},
    approvals: ApprovalHandler = .{},
};

pub const Result = struct {
    term: std.process.Child.Term,
    thread_id: []u8,
    state: ActivityState,
    capabilities: CapabilityProbe,
    turn_completed: bool,
    turn_failed: bool,
    message_count: usize,
    stdout_bytes: usize,
    stderr: process_runner.CapturedStderr,

    pub fn deinit(self: *Result, allocator: std.mem.Allocator) void {
        allocator.free(self.thread_id);
        self.stderr.deinit(allocator);
        self.* = undefined;
    }

    pub fn succeeded(self: Result) bool {
        const clean_exit = switch (self.term) {
            .exited => |code| code == 0,
            else => false,
        };
        return clean_exit and self.turn_completed and !self.turn_failed;
    }
};

pub const ClientError = error{
    InvalidExecutable,
    InvalidConfiguration,
    InvalidThreadId,
    MissingThreadId,
    ConflictingThreadId,
    RpcError,
    ProtocolEnded,
    UnsupportedRequestId,
    UnsupportedCapability,
    UnsafeIntegrationConfiguration,
};

const immutable_developer_instructions =
    "jevx policy is authoritative: stay inside the selected sandbox and workspace; never access credentials or unrelated private data; never use network, external tools, plugins, MCP servers, hooks, delegation, privilege elevation, or sandbox bypass; decline and report any step that needs an approval.";

pub const Argv = struct {
    storage: [39][]const u8 = undefined,

    pub fn slice(self: *const Argv) []const []const u8 {
        return &self.storage;
    }
};

pub fn buildArgv(request: Request) ClientError!Argv {
    if (request.codex_path.len == 0 or std.mem.indexOfScalar(u8, request.codex_path, 0) != null)
        return error.InvalidExecutable;
    return .{ .storage = .{
        request.codex_path,
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
        "-c",
        "analytics.enabled=false",
        "--strict-config",
        "app-server",
        "--listen",
        "stdio://",
    } };
}

/// Runs one complete app-server turn. The app-server process is closed after
/// the terminal turn notification so no idle daemon is leaked.
///
/// `state` is external and sticky. It remains usable on every error path.
pub fn runTurn(
    allocator: std.mem.Allocator,
    io: std.Io,
    request: Request,
    state: *ActivityState,
    sink: EventSink,
) anyerror!Result {
    try validateRequest(request);
    // Codex 0.156.1 app-server has no equivalent of exec's
    // `--ignore-user-config`. Starting it can therefore launch inherited MCP
    // integrations before the first protocol response. Keep the protocol
    // implementation contract-tested, but fail closed before spawning it in
    // production until the pinned CLI provides a verifiable isolation mode.
    if (!builtin.is_test) return error.UnsupportedCapability;
    var argv = try buildArgv(request);

    var child_environment = try process_runner.sanitizeEnvironment(allocator, request.environ_map);
    defer child_environment.deinit();

    var child = try std.process.spawn(io, .{
        .argv = argv.slice(),
        .cwd = if (request.cwd) |path| .{ .path = path } else .inherit,
        .environ_map = &child_environment,
        .stdin = .pipe,
        .stdout = .pipe,
        .stderr = .pipe,
        .create_no_window = true,
    });
    var child_reaped = false;
    defer if (!child_reaped) child.kill(io);

    const stdin_file = child.stdin.?;
    child.stdin = null;
    var stdin_open = true;
    defer if (stdin_open) stdin_file.close(io);

    var multi_buffer: std.Io.File.MultiReader.Buffer(2) = undefined;
    var multi_reader: std.Io.File.MultiReader = undefined;
    multi_reader.init(
        allocator,
        io,
        multi_buffer.toStreams(),
        &.{ child.stdout.?, child.stderr.? },
    );
    defer multi_reader.deinit();

    var streams = StreamState.init(allocator, request.limits);
    defer streams.deinit();
    const timeout = try process_runner.timeoutFromMilliseconds(io, request.limits.timeout_ms);
    var tracker: ProtocolTracker = .{ .state = state };

    const initialize = try encodeInitializeLine(allocator, request);
    defer allocator.free(initialize);
    try sendLine(stdin_file, io, initialize, request.limits.max_line_bytes);
    var init_response = try awaitResponse(
        allocator,
        io,
        stdin_file,
        &multi_reader,
        &streams,
        timeout,
        1,
        &tracker,
        request.approvals,
        sink,
    );
    defer init_response.deinit(allocator);
    if (hasRpcError(init_response.parsed.value)) return error.RpcError;

    const initialized = try encodeInitializedLine(allocator);
    defer allocator.free(initialized);
    try sendLine(stdin_file, io, initialized, request.limits.max_line_bytes);

    const probe = try encodeCapabilityProbeLine(allocator);
    defer allocator.free(probe);
    try sendLine(stdin_file, io, probe, request.limits.max_line_bytes);
    var probe_response = try awaitResponse(
        allocator,
        io,
        stdin_file,
        &multi_reader,
        &streams,
        timeout,
        2,
        &tracker,
        request.approvals,
        sink,
    );
    defer probe_response.deinit(allocator);
    const capabilities = parseCapabilityProbe(probe_response.parsed.value);
    if (!capabilities.supported) return error.UnsupportedCapability;

    const thread_line = try encodeThreadLine(allocator, request);
    defer allocator.free(thread_line);
    try sendLine(stdin_file, io, thread_line, request.limits.max_line_bytes);
    var thread_response = try awaitResponse(
        allocator,
        io,
        stdin_file,
        &multi_reader,
        &streams,
        timeout,
        3,
        &tracker,
        request.approvals,
        sink,
    );
    defer thread_response.deinit(allocator);
    if (hasRpcError(thread_response.parsed.value)) return error.RpcError;
    // Codex currently initializes some user-level integrations before a
    // thread begins, even when the corresponding config maps/features are
    // overridden. Refuse the preview backend before the prompt is submitted
    // whenever the server reports inherited instructions or MCP startup. The
    // caller may then safely fall back to the isolated exec backend.
    if (!threadResponseIsIsolated(thread_response.parsed.value, tracker, request.sandbox))
        return error.UnsafeIntegrationConfiguration;

    const response_thread_id = threadIdFromResponse(thread_response.parsed.value) orelse
        return error.MissingThreadId;
    try validateThreadId(response_thread_id);
    if (request.resume_thread_id) |expected| {
        if (!std.mem.eql(u8, expected, response_thread_id)) return error.ConflictingThreadId;
    }
    const thread_id = try allocator.dupe(u8, response_thread_id);
    errdefer allocator.free(thread_id);

    const turn_line = try encodeTurnStartLine(allocator, request.prompt, thread_id, request.model);
    defer {
        @memset(turn_line, 0);
        allocator.free(turn_line);
    }
    // Once a turn request may have reached the server it must never be replayed
    // through another backend, even if this write or a later read fails.
    state.turn_started = true;
    try sendLine(stdin_file, io, turn_line, request.limits.max_line_bytes);

    var turn_response = try awaitResponse(
        allocator,
        io,
        stdin_file,
        &multi_reader,
        &streams,
        timeout,
        4,
        &tracker,
        request.approvals,
        sink,
    );
    defer turn_response.deinit(allocator);
    if (hasRpcError(turn_response.parsed.value)) return error.RpcError;

    while (!tracker.terminal()) {
        var message = streams.nextMessage(allocator, io, &multi_reader, timeout) catch |err| switch (err) {
            error.EndOfStream => return error.ProtocolEnded,
            else => |other| return other,
        };
        defer message.deinit(allocator);
        _ = try processMessage(allocator, stdin_file, io, &message, &tracker, request.approvals, sink, request.limits.max_line_bytes);
    }

    stdin_file.close(io);
    stdin_open = false;

    // Drain post-turn notifications and stderr until the stdio server observes
    // EOF and exits. No new work is submitted in this phase.
    while (true) {
        var message = streams.nextMessage(allocator, io, &multi_reader, timeout) catch |err| switch (err) {
            error.EndOfStream => break,
            else => |other| return other,
        };
        defer message.deinit(allocator);
        try observeAndEmit(&message, &tracker, sink);
    }
    try multi_reader.checkAnyError();

    const term = try process_runner.waitChild(&child, io, timeout);
    child_reaped = true;
    const stderr_bytes = try streams.stderr_capture.toOwnedSlice(allocator);

    return .{
        .term = term,
        .thread_id = thread_id,
        .state = state.*,
        .capabilities = capabilities,
        .turn_completed = tracker.turn_completed,
        .turn_failed = tracker.turn_failed,
        .message_count = streams.message_count,
        .stdout_bytes = streams.stdout_total,
        .stderr = .{
            .bytes = stderr_bytes,
            .total_bytes = streams.stderr_total,
            .truncated = streams.stderr_total > stderr_bytes.len,
        },
    };
}

pub fn encodeInitializeLine(allocator: std.mem.Allocator, request: Request) ![]u8 {
    return encodeValue(allocator, .{
        .id = 1,
        .method = "initialize",
        .params = .{
            .clientInfo = .{
                .name = request.client_name,
                .title = request.client_title,
                .version = request.client_version,
            },
            .capabilities = .{ .experimentalApi = true },
        },
    });
}

pub fn encodeInitializedLine(allocator: std.mem.Allocator) ![]u8 {
    return encodeValue(allocator, .{ .method = "initialized" });
}

pub fn encodeCapabilityProbeLine(allocator: std.mem.Allocator) ![]u8 {
    return encodeValue(allocator, .{
        .id = 2,
        .method = "modelProvider/capabilities/read",
        .params = .{},
    });
}

pub fn encodeThreadLine(allocator: std.mem.Allocator, request: Request) ![]u8 {
    if (request.resume_thread_id) |thread_id| {
        return encodeValue(allocator, .{
            .id = 3,
            .method = "thread/resume",
            .params = .{
                .threadId = thread_id,
                .cwd = request.cwd,
                .approvalPolicy = "untrusted",
                .approvalsReviewer = "user",
                .sandbox = request.sandbox.cliValue(),
                .model = request.model,
                .excludeTurns = true,
                .developerInstructions = immutable_developer_instructions,
            },
        });
    }
    return encodeValue(allocator, .{
        .id = 3,
        .method = "thread/start",
        .params = .{
            .cwd = request.cwd,
            .approvalPolicy = "untrusted",
            .approvalsReviewer = "user",
            .sandbox = request.sandbox.cliValue(),
            .model = request.model,
            .developerInstructions = immutable_developer_instructions,
        },
    });
}

pub fn encodeTurnStartLine(
    allocator: std.mem.Allocator,
    prompt: []const u8,
    thread_id: []const u8,
    model: ?[]const u8,
) ![]u8 {
    return encodeValue(allocator, .{
        .id = 4,
        .method = "turn/start",
        .params = .{
            .threadId = thread_id,
            .input = &.{.{ .type = "text", .text = prompt }},
            .model = model,
        },
    });
}

fn validateRequest(request: Request) !void {
    _ = try buildArgv(request);
    if (request.limits.max_line_bytes == 0 or
        request.limits.max_stdout_bytes == 0 or
        request.limits.max_stderr_bytes == 0 or
        request.limits.max_events == 0 or
        request.limits.max_line_bytes > request.limits.max_stdout_bytes or
        request.limits.max_stderr_capture_bytes > request.limits.max_stderr_bytes)
    {
        return error.InvalidConfiguration;
    }
    if (request.prompt.len > request.limits.max_input_bytes or
        request.client_name.len == 0 or request.client_name.len > 128 or
        request.client_version.len == 0 or request.client_version.len > 64 or
        request.client_title.len > 256)
    {
        return error.InvalidConfiguration;
    }
    if (request.cwd) |cwd| {
        if (cwd.len == 0 or cwd.len > 4096 or std.mem.indexOfScalar(u8, cwd, 0) != null)
            return error.InvalidConfiguration;
    }
    if (request.resume_thread_id) |id| try validateThreadId(id);
    if (request.model) |model| try validateModel(model);
}

fn validateThreadId(thread_id: []const u8) ClientError!void {
    if (thread_id.len == 0 or thread_id.len > 512 or !std.unicode.utf8ValidateSlice(thread_id))
        return error.InvalidThreadId;
    for (thread_id) |byte| {
        if (byte == 0 or byte == '\n' or byte == '\r' or byte < 0x20 or byte == 0x7f)
            return error.InvalidThreadId;
    }
}

fn validateModel(model: []const u8) ClientError!void {
    if (model.len == 0 or model.len > 256 or !std.unicode.utf8ValidateSlice(model))
        return error.InvalidConfiguration;
    for (model) |byte| {
        if (byte == 0 or byte == '\n' or byte == '\r' or byte < 0x20 or byte == 0x7f)
            return error.InvalidConfiguration;
    }
}

fn encodeValue(allocator: std.mem.Allocator, value: anytype) ![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    try std.json.Stringify.value(value, .{}, &output.writer);
    try output.writer.writeByte('\n');
    return output.toOwnedSlice();
}

fn sendLine(file: std.Io.File, io: std.Io, line: []const u8, max_bytes: usize) !void {
    if (line.len > max_bytes) return error.LineTooLong;
    try file.writeStreamingAll(io, line);
}

const Message = struct {
    index: usize,
    raw: []u8,
    parsed: std.json.Parsed(std.json.Value),

    fn deinit(self: *Message, allocator: std.mem.Allocator) void {
        self.parsed.deinit();
        allocator.free(self.raw);
        self.* = undefined;
    }

    fn event(self: *const Message) process_runner.Event {
        return .{ .index = self.index, .raw = self.raw, .value = &self.parsed.value };
    }
};

const StreamState = struct {
    allocator: std.mem.Allocator,
    limits: process_runner.Limits,
    stdout_line: std.ArrayList(u8) = .empty,
    stderr_capture: std.ArrayList(u8) = .empty,
    stdout_total: usize = 0,
    stderr_total: usize = 0,
    message_count: usize = 0,
    eof: bool = false,

    fn init(allocator: std.mem.Allocator, limits: process_runner.Limits) StreamState {
        return .{ .allocator = allocator, .limits = limits };
    }

    fn deinit(self: *StreamState) void {
        self.stdout_line.deinit(self.allocator);
        self.stderr_capture.deinit(self.allocator);
        self.* = undefined;
    }

    fn nextMessage(
        self: *StreamState,
        allocator: std.mem.Allocator,
        io: std.Io,
        multi_reader: *std.Io.File.MultiReader,
        timeout: std.Io.Timeout,
    ) !Message {
        while (true) {
            try self.drainStderr(multi_reader);
            if (try self.takeStdoutLine(allocator, multi_reader, false)) |message| return message;

            if (self.eof) {
                if (try self.takeStdoutLine(allocator, multi_reader, true)) |message| return message;
                return error.EndOfStream;
            }

            multi_reader.fill(1, timeout) catch |err| switch (err) {
                error.EndOfStream => {
                    self.eof = true;
                    try multi_reader.checkAnyError();
                },
                error.Timeout => return error.ProcessTimeout,
                else => |other| return other,
            };
            _ = io;
        }
    }

    fn takeStdoutLine(
        self: *StreamState,
        allocator: std.mem.Allocator,
        multi_reader: *std.Io.File.MultiReader,
        final_fragment: bool,
    ) !?Message {
        const reader = multi_reader.reader(0);
        const buffered = reader.buffered();

        if (std.mem.indexOfScalar(u8, buffered, '\n')) |newline| {
            try self.accountStdout(newline + 1);
            try self.appendStdoutFragment(buffered[0..newline]);
            reader.toss(newline + 1);
            return try self.parsePending(allocator, false);
        }
        if (buffered.len != 0) {
            try self.accountStdout(buffered.len);
            try self.appendStdoutFragment(buffered);
            reader.toss(buffered.len);
        }
        if (final_fragment and self.stdout_line.items.len != 0)
            return try self.parsePending(allocator, true);
        return null;
    }

    fn accountStdout(self: *StreamState, byte_count: usize) !void {
        self.stdout_total = std.math.add(usize, self.stdout_total, byte_count) catch
            return error.StdoutTooLong;
        if (self.stdout_total > self.limits.max_stdout_bytes) return error.StdoutTooLong;
    }

    fn appendStdoutFragment(self: *StreamState, bytes: []const u8) !void {
        const line_len = std.math.add(usize, self.stdout_line.items.len, bytes.len) catch
            return error.LineTooLong;
        if (line_len > self.limits.max_line_bytes) return error.LineTooLong;
        try self.stdout_line.appendSlice(self.allocator, bytes);
    }

    fn parsePending(self: *StreamState, allocator: std.mem.Allocator, final_fragment: bool) !?Message {
        var line = self.stdout_line.items;
        if (line.len != 0 and line[line.len - 1] == '\r') line = line[0 .. line.len - 1];
        if (isBlank(line)) {
            self.stdout_line.clearRetainingCapacity();
            return null;
        }
        if (self.message_count >= self.limits.max_events) return error.TooManyEvents;

        const raw = try allocator.dupe(u8, line);
        errdefer allocator.free(raw);
        var parsed = process_runner.parseStrict(allocator, raw) catch |err| switch (err) {
            error.MalformedJson => if (final_fragment) return error.TruncatedJson else return error.MalformedJson,
            else => |other| return other,
        };
        errdefer parsed.deinit();
        const index = self.message_count;
        self.message_count += 1;
        self.stdout_line.clearRetainingCapacity();
        return .{ .index = index, .raw = raw, .parsed = parsed };
    }

    fn drainStderr(self: *StreamState, multi_reader: *std.Io.File.MultiReader) !void {
        const reader = multi_reader.reader(1);
        const bytes = reader.buffered();
        if (bytes.len == 0) return;
        self.stderr_total = std.math.add(usize, self.stderr_total, bytes.len) catch
            return error.StderrTooLong;
        if (self.stderr_total > self.limits.max_stderr_bytes) return error.StderrTooLong;
        if (self.stderr_capture.items.len < self.limits.max_stderr_capture_bytes) {
            const room = self.limits.max_stderr_capture_bytes - self.stderr_capture.items.len;
            try self.stderr_capture.appendSlice(self.allocator, bytes[0..@min(room, bytes.len)]);
        }
        reader.toss(bytes.len);
    }
};

const ProtocolTracker = struct {
    state: *ActivityState,
    turn_completed: bool = false,
    turn_failed: bool = false,
    external_integration_started: bool = false,

    fn terminal(self: ProtocolTracker) bool {
        return self.turn_completed or self.turn_failed;
    }

    fn observe(self: *ProtocolTracker, value: std.json.Value) void {
        if (value != .object) return;
        const method = stringField(value.object, "method") orelse return;
        if (std.mem.eql(u8, method, "turn/started")) {
            self.state.turn_started = true;
        } else if (std.mem.eql(u8, method, "turn/completed")) {
            self.turn_completed = true;
        } else if (std.mem.eql(u8, method, "turn/failed")) {
            self.turn_failed = true;
        } else if (std.mem.eql(u8, method, "mcpServer/startupStatus/updated")) {
            self.external_integration_started = true;
        } else if (std.mem.eql(u8, method, "item/started") or
            std.mem.eql(u8, method, "item/updated") or
            std.mem.eql(u8, method, "item/completed"))
        {
            self.observeItem(value.object.get("params") orelse return);
        }
    }

    fn observeItem(self: *ProtocolTracker, params: std.json.Value) void {
        if (params != .object) return;
        const item = params.object.get("item") orelse return;
        if (item != .object) return;
        const item_type = stringField(item.object, "type") orelse return;
        if (std.mem.eql(u8, item_type, "commandExecution") or
            std.mem.eql(u8, item_type, "command_execution"))
        {
            self.state.command_started = true;
        } else if (std.mem.eql(u8, item_type, "fileChange") or
            std.mem.eql(u8, item_type, "file_change") or
            std.mem.eql(u8, item_type, "applyPatch"))
        {
            self.state.file_action_started = true;
        }
    }
};

fn threadResponseIsIsolated(value: std.json.Value, tracker: ProtocolTracker, expected_sandbox: Sandbox) bool {
    if (tracker.external_integration_started or value != .object) return false;
    const result = value.object.get("result") orelse return false;
    if (result != .object) return false;
    const thread = result.object.get("thread") orelse return false;
    if (thread != .object) return false;

    const sources = thread.object.get("instructionSources") orelse return false;
    if (sources != .array or sources.array.items.len != 0) return false;

    const policy = thread.object.get("approvalPolicy") orelse return false;
    if (policy != .string or !std.mem.eql(u8, policy.string, "untrusted")) return false;

    const sandbox = thread.object.get("sandbox") orelse return false;
    if (sandbox != .object) return false;
    const network = sandbox.object.get("networkAccess") orelse return false;
    if (network != .bool or network.bool) return false;
    const sandbox_type = stringField(sandbox.object, "type") orelse return false;
    const type_matches = switch (expected_sandbox) {
        .read_only => std.mem.eql(u8, sandbox_type, "readOnly") or std.mem.eql(u8, sandbox_type, "read-only"),
        .workspace_write => std.mem.eql(u8, sandbox_type, "workspaceWrite") or std.mem.eql(u8, sandbox_type, "workspace-write"),
    };
    if (!type_matches) return false;
    return true;
}

fn awaitResponse(
    allocator: std.mem.Allocator,
    io: std.Io,
    stdin_file: std.Io.File,
    multi_reader: *std.Io.File.MultiReader,
    streams: *StreamState,
    timeout: std.Io.Timeout,
    wanted_id: i64,
    tracker: *ProtocolTracker,
    approvals: ApprovalHandler,
    sink: EventSink,
) !Message {
    while (true) {
        var message = streams.nextMessage(allocator, io, multi_reader, timeout) catch |err| switch (err) {
            error.EndOfStream => return error.ProtocolEnded,
            else => |other| return other,
        };
        errdefer message.deinit(allocator);
        if (try processMessage(allocator, stdin_file, io, &message, tracker, approvals, sink, streams.limits.max_line_bytes)) {
            message.deinit(allocator);
            continue;
        }
        if (responseHasId(message.parsed.value, wanted_id)) return message;
        message.deinit(allocator);
    }
}

/// Returns true when the message was a server-to-client request and therefore
/// cannot also be the client response being awaited.
fn processMessage(
    allocator: std.mem.Allocator,
    stdin_file: std.Io.File,
    io: std.Io,
    message: *const Message,
    tracker: *ProtocolTracker,
    approvals: ApprovalHandler,
    sink: EventSink,
    max_line_bytes: usize,
) !bool {
    try observeAndEmit(message, tracker, sink);
    const object = if (message.parsed.value == .object) message.parsed.value.object else return false;
    const method = stringField(object, "method") orelse return false;
    const id = object.get("id") orelse return false;
    try handleServerRequest(allocator, stdin_file, io, id, method, object.get("params"), tracker.state, approvals, max_line_bytes);
    return true;
}

fn observeAndEmit(message: *const Message, tracker: *ProtocolTracker, sink: EventSink) !void {
    tracker.observe(message.parsed.value);
    try sink.emit(message.event());
}

fn handleServerRequest(
    allocator: std.mem.Allocator,
    stdin_file: std.Io.File,
    io: std.Io,
    id: std.json.Value,
    method: []const u8,
    params_value: ?std.json.Value,
    state: *ActivityState,
    approvals: ApprovalHandler,
    max_line_bytes: usize,
) !void {
    if (id != .integer and id != .string) return error.UnsupportedRequestId;
    const kind: ApprovalKind = if (std.mem.eql(u8, method, "item/commandExecution/requestApproval"))
        .command
    else if (std.mem.eql(u8, method, "item/fileChange/requestApproval"))
        .file_change
    else if (std.mem.eql(u8, method, "item/permissions/requestApproval"))
        .permissions
    else if (std.mem.eql(u8, method, "execCommandApproval"))
        .legacy_command
    else if (std.mem.eql(u8, method, "applyPatchApproval"))
        .legacy_patch
    else
        .unsupported_request;

    const params_ptr: ?*const std.json.Value = if (params_value) |*value| value else null;
    const decision = if (kind == .unsupported_request or kind == .permissions)
        ApprovalDecision.decline
    else
        try approvals.decision(.{ .kind = kind, .method = method, .id = &id, .params = params_ptr });

    if (decision == .accept) switch (kind) {
        .command, .legacy_command => state.command_started = true,
        .file_change, .legacy_patch => state.file_action_started = true,
        else => {},
    };

    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    try output.writer.writeAll("{\"id\":");
    try std.json.Stringify.value(id, .{}, &output.writer);

    switch (kind) {
        .command, .file_change => {
            const wire_decision = switch (decision) {
                .accept => "accept",
                .decline => "decline",
                .cancel => "cancel",
            };
            try output.writer.print(",\"result\":{{\"decision\":\"{s}\"}}}}\n", .{wire_decision});
        },
        .legacy_command, .legacy_patch => switch (decision) {
            .accept => try output.writer.writeAll(",\"result\":{\"decision\":\"approved\"}}\n"),
            .decline => try output.writer.writeAll(",\"result\":{\"decision\":{\"denied\":{\"rejection\":\"Denied by jev-zig-cli policy\"}}}}\n"),
            .cancel => try output.writer.writeAll(",\"result\":{\"decision\":\"abort\"}}\n"),
        },
        .permissions => try output.writer.writeAll(",\"error\":{\"code\":-32000,\"message\":\"Permission escalation denied\"}}\n"),
        .unsupported_request => try output.writer.writeAll(",\"error\":{\"code\":-32601,\"message\":\"Unsupported client request\"}}\n"),
    }
    try sendLine(stdin_file, io, output.written(), max_line_bytes);
}

fn responseHasId(value: std.json.Value, wanted_id: i64) bool {
    if (value != .object or value.object.get("method") != null) return false;
    const id = value.object.get("id") orelse return false;
    return id == .integer and id.integer == wanted_id;
}

fn hasRpcError(value: std.json.Value) bool {
    return value == .object and value.object.get("error") != null;
}

fn parseCapabilityProbe(value: std.json.Value) CapabilityProbe {
    if (hasRpcError(value) or value != .object) return .{};
    const result = value.object.get("result") orelse return .{};
    if (result != .object) return .{};
    return .{
        .supported = true,
        .image_generation = boolField(result.object, "imageGeneration") orelse false,
        .namespace_tools = boolField(result.object, "namespaceTools") orelse false,
        .web_search = boolField(result.object, "webSearch") orelse false,
    };
}

fn threadIdFromResponse(value: std.json.Value) ?[]const u8 {
    if (value != .object) return null;
    const result = value.object.get("result") orelse return null;
    if (result != .object) return null;
    const thread = result.object.get("thread") orelse return null;
    if (thread != .object) return null;
    return stringField(thread.object, "id");
}

fn stringField(object: std.json.ObjectMap, name: []const u8) ?[]const u8 {
    const value = object.get(name) orelse return null;
    return if (value == .string) value.string else null;
}

fn boolField(object: std.json.ObjectMap, name: []const u8) ?bool {
    const value = object.get(name) orelse return null;
    return if (value == .bool) value.bool else null;
}

fn isBlank(bytes: []const u8) bool {
    for (bytes) |byte| switch (byte) {
        ' ', '\t', '\r' => {},
        else => return false,
    };
    return true;
}

fn parseForTest(json: []const u8) !std.json.Parsed(std.json.Value) {
    return process_runner.parseStrict(std.testing.allocator, json);
}

test "app-server argv has no prompt secret or bypass option" {
    const secret = "prompt with sk-secret-value";
    const request: Request = .{ .prompt = secret };
    var argv = try buildArgv(request);
    try std.testing.expectEqualStrings("codex", argv.slice()[0]);
    try std.testing.expect(appServerArgvContains(argv.slice(), "mcp_servers={}"));
    try std.testing.expect(appServerArgvContains(argv.slice(), "features.plugins=false"));
    try std.testing.expect(appServerArgvContains(argv.slice(), "features.browser_use=false"));
    try std.testing.expect(appServerArgvContains(argv.slice(), "app-server"));
    for (argv.slice()) |arg| {
        try std.testing.expect(std.mem.indexOf(u8, arg, secret) == null);
        try std.testing.expect(std.mem.indexOf(u8, arg, "dangerously-bypass") == null);
    }
}

fn appServerArgvContains(argv: []const []const u8, needle: []const u8) bool {
    for (argv) |argument| if (std.mem.eql(u8, argument, needle)) return true;
    return false;
}

test "handshake capability thread and turn messages match JSONL contract" {
    const request: Request = .{
        .prompt = "say \"hello\"",
        .cwd = "/tmp/work",
        .sandbox = .workspace_write,
        .model = "gpt-5.6-codex",
    };
    const initialize = try encodeInitializeLine(std.testing.allocator, request);
    defer std.testing.allocator.free(initialize);
    const initialized = try encodeInitializedLine(std.testing.allocator);
    defer std.testing.allocator.free(initialized);
    const probe = try encodeCapabilityProbeLine(std.testing.allocator);
    defer std.testing.allocator.free(probe);
    const thread = try encodeThreadLine(std.testing.allocator, request);
    defer std.testing.allocator.free(thread);
    const turn = try encodeTurnStartLine(std.testing.allocator, request.prompt, "thread-1", request.model);
    defer std.testing.allocator.free(turn);

    try std.testing.expect(std.mem.indexOf(u8, initialize, "\"method\":\"initialize\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, initialize, "\"experimentalApi\":true") != null);
    try std.testing.expectEqualStrings("{\"method\":\"initialized\"}\n", initialized);
    try std.testing.expect(std.mem.indexOf(u8, probe, "modelProvider/capabilities/read") != null);
    try std.testing.expect(std.mem.indexOf(u8, thread, "\"method\":\"thread/start\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, thread, "\"approvalPolicy\":\"untrusted\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, thread, "\"developerInstructions\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, thread, "\"sandbox\":\"workspace-write\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, thread, "\"model\":\"gpt-5.6-codex\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, turn, "\"method\":\"turn/start\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, turn, "say \\\"hello\\\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, turn, "\"model\":\"gpt-5.6-codex\"") != null);
}

test "resume message preserves thread id" {
    const request: Request = .{ .prompt = "next", .resume_thread_id = "thread-old" };
    const line = try encodeThreadLine(std.testing.allocator, request);
    defer std.testing.allocator.free(line);
    try std.testing.expect(std.mem.indexOf(u8, line, "\"method\":\"thread/resume\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "\"threadId\":\"thread-old\"") != null);
}

test "protocol tracker marks command file and terminal events" {
    var state: ActivityState = .{};
    var tracker: ProtocolTracker = .{ .state = &state };
    const messages = [_][]const u8{
        "{\"method\":\"turn/started\",\"params\":{\"future\":1}}",
        "{\"method\":\"item/started\",\"params\":{\"item\":{\"type\":\"commandExecution\"}}}",
        "{\"method\":\"item/completed\",\"params\":{\"item\":{\"type\":\"fileChange\"}}}",
        "{\"method\":\"turn/completed\",\"params\":{}}",
    };
    for (messages) |json| {
        var parsed = try parseForTest(json);
        defer parsed.deinit();
        tracker.observe(parsed.value);
    }
    try std.testing.expect(state.turn_started);
    try std.testing.expect(state.command_started);
    try std.testing.expect(state.file_action_started);
    try std.testing.expect(!state.mayFallback());
    try std.testing.expect(tracker.turn_completed);
}

test "app-server refuses inherited instructions and external integrations" {
    var state: ActivityState = .{};
    var tracker: ProtocolTracker = .{ .state = &state };

    var safe = try parseForTest(
        "{\"id\":3,\"result\":{\"thread\":{\"id\":\"thread-1\",\"instructionSources\":[],\"approvalPolicy\":\"untrusted\",\"sandbox\":{\"type\":\"readOnly\",\"networkAccess\":false}}}}",
    );
    defer safe.deinit();
    try std.testing.expect(threadResponseIsIsolated(safe.value, tracker, .read_only));

    var inherited = try parseForTest(
        "{\"id\":3,\"result\":{\"thread\":{\"id\":\"thread-1\",\"instructionSources\":[\"/private/AGENTS.md\"]}}}",
    );
    defer inherited.deinit();
    try std.testing.expect(!threadResponseIsIsolated(inherited.value, tracker, .read_only));

    var startup = try parseForTest(
        "{\"method\":\"mcpServer/startupStatus/updated\",\"params\":{\"name\":\"external\"}}",
    );
    defer startup.deinit();
    tracker.observe(startup.value);
    try std.testing.expect(tracker.external_integration_started);
    try std.testing.expect(!threadResponseIsIsolated(safe.value, tracker, .read_only));
}

test "capability probe tolerates unknown fields and rpc rejection" {
    var parsed = try parseForTest("{\"id\":2,\"result\":{\"imageGeneration\":true,\"namespaceTools\":false,\"webSearch\":true,\"future\":7}}");
    defer parsed.deinit();
    const capabilities = parseCapabilityProbe(parsed.value);
    try std.testing.expect(capabilities.supported);
    try std.testing.expect(capabilities.image_generation);
    try std.testing.expect(capabilities.web_search);

    var rejected = try parseForTest("{\"id\":2,\"error\":{\"code\":-32601,\"message\":\"unknown\"}}");
    defer rejected.deinit();
    try std.testing.expect(!parseCapabilityProbe(rejected.value).supported);
}

fn acceptFixtureApproval(_: ?*anyopaque, request: ApprovalRequest) !ApprovalDecision {
    return if (request.kind == .command) .accept else .decline;
}

test "fake app-server fixture completes handshake approval and turn" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;

    const script =
        \\#!/bin/sh
        \\[ -z "${OPENROUTER_API_KEY+x}" ] || exit 22
        \\[ "$CODEX_HOME" = /safe/codex ] || exit 23
        \\printf 'hostile-stderr-isolated' >&2
        \\while IFS= read -r line; do
        \\  case "$line" in
        \\    *'"id":1'*'"method":"initialize"'*)
        \\      printf '%s\n' '{"id":1,"result":{"codexHome":"/tmp","platformFamily":"unix","platformOs":"macos","userAgent":"fixture"}}'
        \\      ;;
        \\    *'"method":"initialized"'*) ;;
        \\    *'"id":2'*'modelProvider/capabilities/read'*)
        \\      printf '%s\n' '{"id":2,"result":{"imageGeneration":false,"namespaceTools":true,"webSearch":true,"unknown":1}}'
        \\      ;;
        \\    *'"id":3'*'"method":"thread/start"'*)
        \\      printf '%s\n' '{"id":3,"result":{"thread":{"id":"fixture-thread","instructionSources":[],"approvalPolicy":"untrusted","sandbox":{"type":"readOnly","networkAccess":false}},"future":"ok"}}'
        \\      ;;
        \\    *'"id":4'*'"method":"turn/start"'*)
        \\      printf '%s\n' '{"id":4,"result":{"turn":{"id":"turn-1"}}}'
        \\      printf '%s\n' '{"method":"turn/started","params":{"turn":{"id":"turn-1"}}}'
        \\      printf '%s\n' '{"id":"approval-1","method":"item/commandExecution/requestApproval","params":{"threadId":"fixture-thread"}}'
        \\      ;;
        \\    *'"id":"approval-1"'*'"decision":"accept"'*)
        \\      printf '%s\n' '{"method":"item/started","params":{"item":{"type":"commandExecution","id":"item-1"}}}'
        \\      printf '%s\n' '{"method":"turn/completed","params":{"turn":{"id":"turn-1"}}}'
        \\      ;;
        \\  esac
        \\done
    ;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const fake = try tmp.dir.createFile(std.testing.io, "fake-codex", .{
        .permissions = .executable_file,
    });
    try fake.writeStreamingAll(std.testing.io, script);
    fake.close(std.testing.io);
    const fake_path = try tmp.dir.realPathFileAlloc(std.testing.io, "fake-codex", std.testing.allocator);
    defer std.testing.allocator.free(fake_path);

    var source_environment = std.process.Environ.Map.init(std.testing.allocator);
    defer source_environment.deinit();
    try source_environment.put("PATH", "/usr/bin:/bin");
    try source_environment.put("CODEX_HOME", "/safe/codex");
    try source_environment.put("OPENROUTER_API_KEY", "sentinel-must-not-reach-app-server");

    var state: ActivityState = .{};
    var result = try runTurn(std.testing.allocator, std.testing.io, .{
        .codex_path = fake_path,
        .environ_map = &source_environment,
        .prompt = "fixture prompt stays on stdin",
        .model = "gpt-5.6-codex",
        .limits = .{ .timeout_ms = 5_000, .max_stderr_capture_bytes = 7 },
        .approvals = .{ .decide = acceptFixtureApproval },
    }, &state, .{});
    defer result.deinit(std.testing.allocator);

    try std.testing.expect(result.succeeded());
    try std.testing.expectEqualStrings("fixture-thread", result.thread_id);
    try std.testing.expect(result.capabilities.supported);
    try std.testing.expect(result.capabilities.namespace_tools);
    try std.testing.expect(state.turn_started);
    try std.testing.expect(state.command_started);
    try std.testing.expect(!state.mayFallback());
    try std.testing.expectEqualStrings("hostile", result.stderr.bytes);
    try std.testing.expect(result.stderr.truncated);
}

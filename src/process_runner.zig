//! Bounded child-process and JSONL streaming support.
//!
//! The child receives its input exclusively through stdin. Stdout is decoded one
//! JSON value at a time and delivered synchronously, which deliberately applies
//! backpressure to a fast producer. Stderr is drained independently, never
//! interpreted as protocol data, and only a bounded prefix is retained.

const std = @import("std");

pub const Limits = struct {
    max_input_bytes: usize = 4 * 1024 * 1024,
    max_line_bytes: usize = 1024 * 1024,
    max_stdout_bytes: usize = 32 * 1024 * 1024,
    max_stderr_bytes: usize = 16 * 1024 * 1024,
    max_stderr_capture_bytes: usize = 64 * 1024,
    max_events: usize = 100_000,
    timeout_ms: ?u64 = 30 * 60 * 1000,
};

pub const Event = struct {
    index: usize,
    raw: []const u8,
    value: *const std.json.Value,
};

/// A synchronous callback is intentional: the producer cannot outrun the
/// consumer without eventually blocking on the stdout pipe.
pub const EventSink = struct {
    context: ?*anyopaque = null,
    on_event: ?*const fn (context: ?*anyopaque, event: Event) anyerror!void = null,

    pub fn emit(self: EventSink, event: Event) !void {
        if (self.on_event) |callback| try callback(self.context, event);
    }
};

pub const CapturedStderr = struct {
    bytes: []u8,
    total_bytes: usize,
    truncated: bool,

    pub fn deinit(self: *CapturedStderr, allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub const Result = struct {
    term: std.process.Child.Term,
    event_count: usize,
    stdout_bytes: usize,
    stderr: CapturedStderr,

    pub fn deinit(self: *Result, allocator: std.mem.Allocator) void {
        self.stderr.deinit(allocator);
        self.* = undefined;
    }

    pub fn succeeded(self: Result) bool {
        return switch (self.term) {
            .exited => |code| code == 0,
            else => false,
        };
    }
};

pub const RunOptions = struct {
    argv: []const []const u8,
    cwd: std.process.Child.Cwd = .inherit,
    /// Source environment. A fresh allowlisted copy is always passed to the
    /// child. Null means an empty child environment, never implicit inherit.
    environ_map: ?*const std.process.Environ.Map = null,
    environment_policy: EnvironmentPolicy = .sanitized,
    stdin_data: []const u8 = &.{},
    limits: Limits = .{},
    sink: EventSink = .{},
};

pub const EnvironmentPolicy = enum {
    /// Default for Codex and arbitrary children: retain only the explicit safe
    /// allowlist implemented by `sanitizeEnvironment`.
    sanitized,
    /// Use the caller-provided map exactly. Callers must construct a dedicated
    /// least-privilege map; this is used for the Jev helper's one required key.
    exact,
};

pub const ProtocolError = error{
    EmptyArgv,
    InputTooLong,
    InvalidLimit,
    InvalidTimeout,
    LineTooLong,
    StdoutTooLong,
    StderrTooLong,
    TooManyEvents,
    MalformedJson,
    DuplicateJsonField,
    TruncatedJson,
    ProcessTimeout,
};

/// Builds the only environment representation accepted by child processes in
/// this module. API keys, cloud credentials, bearer tokens, auth sockets, and
/// arbitrary application variables are absent by construction. `CODEX_HOME`
/// is explicitly retained because installed Codex authentication may depend on
/// it; API keys such as `OPENAI_API_KEY` are intentionally not retained.
pub fn sanitizeEnvironment(
    allocator: std.mem.Allocator,
    source: ?*const std.process.Environ.Map,
) !std.process.Environ.Map {
    var result = std.process.Environ.Map.init(allocator);
    errdefer result.deinit();
    const input = source orelse return result;
    for (input.keys(), input.values()) |key, value| {
        if (environmentVariableAllowed(key)) try result.put(key, value);
    }
    return result;
}

pub fn environmentVariableAllowed(name: []const u8) bool {
    const exact = [_][]const u8{
        "PATH",                "HOME",        "CODEX_HOME",    "USER",            "LOGNAME",        "SHELL",
        "TMPDIR",              "TMP",         "TEMP",          "TZ",              "LANG",           "TERM",
        "COLORTERM",           "NO_COLOR",    "FORCE_COLOR",   "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME",
        "XDG_STATE_HOME",      "USERPROFILE", "APPDATA",       "LOCALAPPDATA",    "SYSTEMROOT",     "WINDIR",
        "COMSPEC",             "PATHEXT",     "SSL_CERT_FILE", "SSL_CERT_DIR",    "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE",
        "NODE_EXTRA_CA_CERTS",
    };
    for (exact) |allowed| {
        if (std.ascii.eqlIgnoreCase(name, allowed)) return true;
    }
    return name.len > 3 and std.ascii.startsWithIgnoreCase(name, "LC_");
}

/// Incremental, strict JSONL decoder. Unknown object fields are retained in
/// `std.json.Value`; duplicate object fields are rejected at every depth.
pub const JsonlDecoder = struct {
    allocator: std.mem.Allocator,
    limits: Limits,
    pending: std.ArrayList(u8) = .empty,
    total_bytes: usize = 0,
    event_count: usize = 0,
    finished: bool = false,

    pub fn init(allocator: std.mem.Allocator, limits: Limits) JsonlDecoder {
        return .{ .allocator = allocator, .limits = limits };
    }

    pub fn deinit(self: *JsonlDecoder) void {
        self.pending.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn feed(self: *JsonlDecoder, bytes: []const u8, sink: EventSink) !void {
        if (self.finished) return error.MalformedJson;
        self.total_bytes = std.math.add(usize, self.total_bytes, bytes.len) catch
            return error.StdoutTooLong;
        if (self.total_bytes > self.limits.max_stdout_bytes) return error.StdoutTooLong;

        var rest = bytes;
        while (std.mem.indexOfScalar(u8, rest, '\n')) |newline| {
            const fragment = rest[0..newline];
            try self.appendFragment(fragment);
            try self.consumePending(sink, false);
            rest = rest[newline + 1 ..];
        }
        try self.appendFragment(rest);
    }

    /// Accepts a valid final JSON value without a newline. If a non-empty final
    /// fragment is not valid JSON, it is reported as truncated input.
    pub fn finish(self: *JsonlDecoder, sink: EventSink) !void {
        if (self.finished) return;
        self.finished = true;
        if (isBlank(self.pending.items)) {
            self.pending.clearRetainingCapacity();
            return;
        }
        self.consumePending(sink, true) catch |err| switch (err) {
            error.MalformedJson => return error.TruncatedJson,
            else => |other| return other,
        };
    }

    fn appendFragment(self: *JsonlDecoder, fragment: []const u8) !void {
        const new_len = std.math.add(usize, self.pending.items.len, fragment.len) catch
            return error.LineTooLong;
        if (new_len > self.limits.max_line_bytes) return error.LineTooLong;
        try self.pending.appendSlice(self.allocator, fragment);
    }

    fn consumePending(self: *JsonlDecoder, sink: EventSink, final_fragment: bool) !void {
        var line = self.pending.items;
        if (line.len != 0 and line[line.len - 1] == '\r') line = line[0 .. line.len - 1];
        if (isBlank(line)) {
            self.pending.clearRetainingCapacity();
            return;
        }
        if (self.event_count >= self.limits.max_events) return error.TooManyEvents;

        var parsed = parseStrict(self.allocator, line) catch |err| switch (err) {
            error.DuplicateJsonField => return error.DuplicateJsonField,
            error.OutOfMemory => return error.OutOfMemory,
            else => if (final_fragment) return error.MalformedJson else return error.MalformedJson,
        };
        defer parsed.deinit();

        const index = self.event_count;
        self.event_count += 1;
        try sink.emit(.{ .index = index, .raw = line, .value = &parsed.value });
        self.pending.clearRetainingCapacity();
    }
};

pub fn parseStrict(
    allocator: std.mem.Allocator,
    input: []const u8,
) (ProtocolError || std.mem.Allocator.Error)!std.json.Parsed(std.json.Value) {
    return std.json.parseFromSlice(std.json.Value, allocator, input, .{
        .duplicate_field_behavior = .@"error",
        .max_value_len = input.len,
        .allocate = .alloc_always,
    }) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.DuplicateField => error.DuplicateJsonField,
        else => error.MalformedJson,
    };
}

/// Runs a process with piped stdin/stdout/stderr. Nothing from `stdin_data` is
/// placed in argv or the environment by this function.
pub fn run(
    allocator: std.mem.Allocator,
    io: std.Io,
    options: RunOptions,
) anyerror!Result {
    try validateLimits(options.limits);
    if (options.argv.len == 0) return error.EmptyArgv;
    if (options.stdin_data.len > options.limits.max_input_bytes) return error.InputTooLong;

    var child_environment = switch (options.environment_policy) {
        .sanitized => try sanitizeEnvironment(allocator, options.environ_map),
        .exact => if (options.environ_map) |source|
            try source.clone(allocator)
        else
            std.process.Environ.Map.init(allocator),
    };
    defer {
        if (options.environment_policy == .exact) {
            var iterator = child_environment.iterator();
            while (iterator.next()) |entry| std.crypto.secureZero(u8, @constCast(entry.value_ptr.*));
        }
        child_environment.deinit();
    }

    var child = try std.process.spawn(io, .{
        .argv = options.argv,
        .cwd = options.cwd,
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
    var input_future = io.async(writeInputAndClose, .{ stdin_file, io, options.stdin_data });
    var input_done = false;
    defer if (!input_done) {
        _ = input_future.cancel(io) catch {};
    };

    var multi_buffer: std.Io.File.MultiReader.Buffer(2) = undefined;
    var multi_reader: std.Io.File.MultiReader = undefined;
    multi_reader.init(
        allocator,
        io,
        multi_buffer.toStreams(),
        &.{ child.stdout.?, child.stderr.? },
    );
    defer multi_reader.deinit();

    var decoder = JsonlDecoder.init(allocator, options.limits);
    defer decoder.deinit();
    var stderr_capture: std.ArrayList(u8) = .empty;
    defer stderr_capture.deinit(allocator);
    var stderr_total: usize = 0;

    const timeout = try timeoutFromMilliseconds(io, options.limits.timeout_ms);
    while (true) {
        try drainStdout(&multi_reader, &decoder, options.sink);
        try drainStderr(
            allocator,
            &multi_reader,
            &stderr_capture,
            &stderr_total,
            options.limits,
        );

        multi_reader.fill(1, timeout) catch |err| switch (err) {
            error.EndOfStream => break,
            error.Timeout => return error.ProcessTimeout,
            else => |other| return other,
        };
    }

    // A completed operation may have populated buffers in the same fill call
    // that observed the last EOF.
    try drainStdout(&multi_reader, &decoder, options.sink);
    try drainStderr(
        allocator,
        &multi_reader,
        &stderr_capture,
        &stderr_total,
        options.limits,
    );
    try multi_reader.checkAnyError();
    try decoder.finish(options.sink);

    try input_future.await(io);
    input_done = true;

    const term = try waitChild(&child, io, timeout);
    child_reaped = true;

    const captured = try stderr_capture.toOwnedSlice(allocator);
    return .{
        .term = term,
        .event_count = decoder.event_count,
        .stdout_bytes = decoder.total_bytes,
        .stderr = .{
            .bytes = captured,
            .total_bytes = stderr_total,
            .truncated = stderr_total > captured.len,
        },
    };
}

fn validateLimits(limits: Limits) !void {
    if (limits.max_line_bytes == 0 or
        limits.max_stdout_bytes == 0 or
        limits.max_stderr_bytes == 0 or
        limits.max_events == 0 or
        limits.max_line_bytes > limits.max_stdout_bytes or
        limits.max_stderr_capture_bytes > limits.max_stderr_bytes)
    {
        return error.InvalidLimit;
    }
}

pub fn timeoutFromMilliseconds(io: std.Io, timeout_ms: ?u64) !std.Io.Timeout {
    const raw_ms = timeout_ms orelse return .none;
    const millis = std.math.cast(i64, raw_ms) orelse return error.InvalidTimeout;
    const duration: std.Io.Clock.Duration = .{
        .raw = std.Io.Duration.fromMilliseconds(millis),
        .clock = .awake,
    };
    return .{ .deadline = .fromNow(io, duration) };
}

fn writeInputAndClose(file: std.Io.File, io: std.Io, bytes: []const u8) !void {
    defer file.close(io);
    try file.writeStreamingAll(io, bytes);
}

fn drainStdout(
    multi_reader: *std.Io.File.MultiReader,
    decoder: *JsonlDecoder,
    sink: EventSink,
) !void {
    const reader = multi_reader.reader(0);
    const bytes = reader.buffered();
    if (bytes.len == 0) return;
    try decoder.feed(bytes, sink);
    reader.toss(bytes.len);
}

fn drainStderr(
    allocator: std.mem.Allocator,
    multi_reader: *std.Io.File.MultiReader,
    capture: *std.ArrayList(u8),
    total: *usize,
    limits: Limits,
) !void {
    const reader = multi_reader.reader(1);
    const bytes = reader.buffered();
    if (bytes.len == 0) return;
    total.* = std.math.add(usize, total.*, bytes.len) catch return error.StderrTooLong;
    if (total.* > limits.max_stderr_bytes) return error.StderrTooLong;

    if (capture.items.len < limits.max_stderr_capture_bytes) {
        const room = limits.max_stderr_capture_bytes - capture.items.len;
        try capture.appendSlice(allocator, bytes[0..@min(room, bytes.len)]);
    }
    reader.toss(bytes.len);
}

pub fn waitChild(
    child: *std.process.Child,
    io: std.Io,
    timeout: std.Io.Timeout,
) !std.process.Child.Term {
    if (timeout == .none) return child.wait(io);

    const WaitResult = union(enum) {
        child: std.process.Child.WaitError!std.process.Child.Term,
        timer: std.Io.Cancelable!void,
    };
    var buffer: [2]WaitResult = undefined;
    var select = std.Io.Select(WaitResult).init(io, &buffer);
    select.async(.child, std.process.Child.wait, .{ child, io });
    select.async(.timer, std.Io.Timeout.sleep, .{ timeout, io });

    const first = try select.await();
    switch (first) {
        .child => |result| {
            select.cancelDiscard();
            return try result;
        },
        .timer => |result| {
            try result;
            select.cancelDiscard();
            return error.ProcessTimeout;
        },
    }
}

fn isBlank(bytes: []const u8) bool {
    for (bytes) |byte| switch (byte) {
        ' ', '\t', '\r' => {},
        else => return false,
    };
    return true;
}

const TestCollector = struct {
    count: usize = 0,
    last_was_two: bool = false,
    last_was_clean: bool = false,

    fn receive(context: ?*anyopaque, event: Event) !void {
        const self: *TestCollector = @ptrCast(@alignCast(context.?));
        self.count += 1;
        if (event.value.* == .object) {
            if (event.value.object.get("type")) |value| {
                if (value == .string) {
                    self.last_was_two = std.mem.eql(u8, value.string, "two");
                    self.last_was_clean = std.mem.eql(u8, value.string, "clean");
                }
            }
        }
    }

    fn sink(self: *TestCollector) EventSink {
        return .{ .context = self, .on_event = receive };
    }
};

test "JSONL decoder streams values and accepts unknown fields" {
    var collector: TestCollector = .{};
    var decoder = JsonlDecoder.init(std.testing.allocator, .{});
    defer decoder.deinit();

    try decoder.feed("{\"type\":\"one\",\"future\":{\"x\":1}}\n{\"ty", collector.sink());
    try decoder.feed("pe\":\"two\"}\r\n", collector.sink());
    try decoder.finish(collector.sink());
    try std.testing.expectEqual(@as(usize, 2), collector.count);
    try std.testing.expect(collector.last_was_two);
}

test "JSONL decoder rejects malformed duplicate oversized and truncated input" {
    {
        var decoder = JsonlDecoder.init(std.testing.allocator, .{});
        defer decoder.deinit();
        try std.testing.expectError(error.DuplicateJsonField, decoder.feed("{\"x\":1,\"x\":2}\n", .{}));
    }
    {
        var decoder = JsonlDecoder.init(std.testing.allocator, .{});
        defer decoder.deinit();
        try std.testing.expectError(error.MalformedJson, decoder.feed("not-json\n", .{}));
    }
    {
        var decoder = JsonlDecoder.init(std.testing.allocator, .{ .max_line_bytes = 4 });
        defer decoder.deinit();
        try std.testing.expectError(error.LineTooLong, decoder.feed("{\"x\":1}", .{}));
    }
    {
        var decoder = JsonlDecoder.init(std.testing.allocator, .{});
        defer decoder.deinit();
        try decoder.feed("{\"x\":", .{});
        try std.testing.expectError(error.TruncatedJson, decoder.finish(.{}));
    }
}

test "runner sends input only over stdin and isolates hostile stderr" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;

    var collector: TestCollector = .{};
    var result = try run(std.testing.allocator, std.testing.io, .{
        .argv = &.{
            "/bin/sh",
            "-c",
            "IFS= read -r line; [ \"$line\" = 'sensitive prompt' ] || exit 9; printf '{\\\"type\\\":\\\"ok\\\"}\\n'; printf 'stderr-is-not-json' >&2",
        },
        .stdin_data = "sensitive prompt\n",
        .limits = .{ .max_stderr_capture_bytes = 7 },
        .sink = collector.sink(),
    });
    defer result.deinit(std.testing.allocator);

    try std.testing.expect(result.succeeded());
    try std.testing.expectEqual(@as(usize, 1), collector.count);
    try std.testing.expectEqualStrings("stderr-", result.stderr.bytes);
    try std.testing.expect(result.stderr.truncated);
}

test "child environment retains Codex paths and strips credential sentinels" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;

    var source = std.process.Environ.Map.init(std.testing.allocator);
    defer source.deinit();
    try source.put("PATH", "/usr/bin:/bin");
    try source.put("HOME", "/safe/home");
    try source.put("CODEX_HOME", "/safe/codex");
    try source.put("OPENROUTER_API_KEY", "sentinel-must-not-reach-child");
    try source.put("OPENAI_API_KEY", "also-secret");
    try source.put("AWS_SECRET_ACCESS_KEY", "cloud-secret");
    try source.put("MY_PRIVATE_TOKEN", "token-secret");

    var sanitized = try sanitizeEnvironment(std.testing.allocator, &source);
    defer sanitized.deinit();
    try std.testing.expectEqualStrings("/usr/bin:/bin", sanitized.get("PATH").?);
    try std.testing.expectEqualStrings("/safe/home", sanitized.get("HOME").?);
    try std.testing.expectEqualStrings("/safe/codex", sanitized.get("CODEX_HOME").?);
    try std.testing.expect(sanitized.get("OPENROUTER_API_KEY") == null);
    try std.testing.expect(sanitized.get("OPENAI_API_KEY") == null);
    try std.testing.expect(sanitized.get("AWS_SECRET_ACCESS_KEY") == null);
    try std.testing.expect(sanitized.get("MY_PRIVATE_TOKEN") == null);

    var collector: TestCollector = .{};
    var result = try run(std.testing.allocator, std.testing.io, .{
        .argv = &.{
            "/bin/sh",
            "-c",
            "if [ -z \"${OPENROUTER_API_KEY+x}\" ] && [ \"$CODEX_HOME\" = /safe/codex ]; then printf '{\\\"type\\\":\\\"clean\\\"}\\n'; else printf '{\\\"type\\\":\\\"leak\\\"}\\n'; fi",
        },
        .environ_map = &source,
        .sink = collector.sink(),
    });
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(result.succeeded());
    try std.testing.expect(collector.last_was_clean);
}

test "runner times out and reaps a stalled child" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;
    try std.testing.expectError(error.ProcessTimeout, run(std.testing.allocator, std.testing.io, .{
        .argv = &.{ "/bin/sleep", "1" },
        .limits = .{ .timeout_ms = 20 },
    }));
}

test "runner preserves signal termination" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;
    var result = try run(std.testing.allocator, std.testing.io, .{
        .argv = &.{ "/bin/sh", "-c", "kill -TERM $$" },
    });
    defer result.deinit(std.testing.allocator);
    switch (result.term) {
        .signal => |signal| try std.testing.expectEqual(std.posix.SIG.TERM, signal),
        else => return error.TestUnexpectedResult,
    }
}

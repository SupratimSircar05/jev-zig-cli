//! Executes a real fake Codex child and verifies the production event
//! sanitizer before any event becomes output or postflight evidence.

const std = @import("std");
const jevx = @import("jevx");

const guarded_prompt = "integration guarded prompt: exact private prompt";
const user_prompt = "exact private prompt";

const Capture = struct {
    allocator: std.mem.Allocator,
    bytes: std.ArrayList(u8) = .empty,

    fn deinit(self: *Capture) void {
        self.bytes.deinit(self.allocator);
        self.* = undefined;
    }

    fn receive(raw_context: ?*anyopaque, event: jevx.process_runner.Event) !void {
        const self: *Capture = @ptrCast(@alignCast(raw_context.?));
        const safe = try jevx.output_sanitizer.sanitizeJson(
            self.allocator,
            event.value.*,
            guarded_prompt,
            user_prompt,
        );
        defer {
            std.crypto.secureZero(u8, safe);
            self.allocator.free(safe);
        }
        try self.bytes.appendSlice(self.allocator, safe);
        try self.bytes.append(self.allocator, '\n');
    }
};

const Counter = struct {
    count: usize = 0,

    fn receive(raw_context: ?*anyopaque, _: jevx.process_runner.Event) !void {
        const self: *Counter = @ptrCast(@alignCast(raw_context.?));
        self.count += 1;
    }
};

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 2) return error.MissingFakeCodexPath;

    var capture: Capture = .{ .allocator = init.gpa };
    defer capture.deinit();
    var activity: jevx.codex_exec.ActivityState = .{};
    var result = try jevx.codex_exec.execute(
        init.gpa,
        init.io,
        .{
            .codex_path = args[1],
            .environ_map = init.environ_map,
            .prompt = guarded_prompt,
            .sandbox = .read_only,
            .limits = .{
                .max_input_bytes = 4096,
                .max_line_bytes = 4096,
                .max_stdout_bytes = 16 * 1024,
                .max_stderr_bytes = 4096,
                .max_stderr_capture_bytes = 4096,
                .max_events = 8,
                .timeout_ms = 10_000,
            },
        },
        &activity,
        .{ .context = &capture, .on_event = Capture.receive },
    );
    defer result.deinit(init.gpa);

    try require(result.succeeded());
    try require(result.process.event_count == 3);
    try require(result.state.turn_started);
    try require(result.thread_id != null);
    try require(std.mem.eql(u8, result.thread_id.?, "integration-thread"));

    for ([_][]const u8{
        "opaque-auth-value",
        "opaque-api-value",
        "opaque-object-value",
        "opaque-session-value",
        guarded_prompt,
        user_prompt,
        "sk-secret",
    }) |secret| try require(std.mem.indexOf(u8, capture.bytes.items, secret) == null);
    try require(std.mem.indexOf(u8, capture.bytes.items, jevx.redact.marker) != null);
    try require(std.mem.indexOf(u8, capture.bytes.items, "[PROMPT REDACTED]") != null);
    try require(std.mem.indexOf(u8, capture.bytes.items, "\"future_field\":\"kept\"") != null);

    var counter: Counter = .{};
    var decoder = jevx.process_runner.JsonlDecoder.init(init.gpa, .{
        .max_line_bytes = 4096,
        .max_stdout_bytes = 16 * 1024,
        .max_events = 8,
    });
    defer decoder.deinit();
    const sink: jevx.process_runner.EventSink = .{ .context = &counter, .on_event = Counter.receive };
    try decoder.feed(capture.bytes.items, sink);
    try decoder.finish(sink);
    try require(counter.count == 3);
}

fn require(condition: bool) !void {
    if (!condition) return error.IntegrationAssertionFailed;
}

const std = @import("std");

pub const EventType = enum {
    session_started,
    service_ready,
    policy_result,
    backend_event,
    decision,
    audit_recorded,
    warning,
    error_,
    completed,
};

pub const Emitter = struct {
    writer: *std.Io.Writer,
    io: std.Io,
    session_id: []const u8,
    turn_id: ?[]const u8 = null,
    sequence: u64 = 0,

    pub fn emit(self: *Emitter, event_type: EventType, data: anytype) !void {
        self.sequence += 1;
        const now = std.Io.Clock.real.now(self.io);
        const envelope = .{
            .schema_version = "jevx.event.v1",
            .sequence = self.sequence,
            .timestamp_unix_ns = now.nanoseconds,
            .session_id = self.session_id,
            .turn_id = self.turn_id,
            .event_type = @tagName(event_type),
            .data = data,
        };
        try std.json.Stringify.value(envelope, .{}, self.writer);
        try self.writer.writeByte('\n');
        try self.writer.flush();
    }
};

test "event envelope is versioned and sequenced" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var emitter: Emitter = .{ .writer = &out.writer, .io = std.testing.io, .session_id = "s1" };
    try emitter.emit(.completed, .{ .ok = true });
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "\"schema_version\":\"jevx.event.v1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "\"sequence\":1") != null);
}

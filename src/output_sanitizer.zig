//! Key-aware sanitization for untrusted structured backend events.
//!
//! Backend schemas can add fields without warning. Text-pattern redaction is
//! not sufficient for opaque credentials, so values under sensitive keys are
//! replaced wholesale before they can reach JSONL output or Jev postflight
//! evidence. String values also receive ordinary text and exact-prompt
//! redaction, while object keys are preserved for schema compatibility.

const std = @import("std");
const redact = @import("redact.zig");

pub fn sanitizeText(
    allocator: std.mem.Allocator,
    input: []const u8,
    full_prompt: []const u8,
    user_prompt: []const u8,
) ![]u8 {
    var current = try redact.redactText(allocator, input);
    errdefer {
        std.crypto.secureZero(u8, current);
        allocator.free(current);
    }
    const needles = [_][]const u8{ full_prompt, user_prompt };
    for (needles) |needle| {
        if (needle.len == 0 or std.mem.indexOf(u8, current, needle) == null) continue;
        const replaced = try std.mem.replaceOwned(u8, allocator, current, needle, "[PROMPT REDACTED]");
        std.crypto.secureZero(u8, current);
        allocator.free(current);
        current = replaced;
    }
    return current;
}

pub fn sanitizeJson(
    allocator: std.mem.Allocator,
    value: std.json.Value,
    full_prompt: []const u8,
    user_prompt: []const u8,
) ![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    writeJson(allocator, &output.writer, value, full_prompt, user_prompt) catch |err| switch (err) {
        error.WriteFailed => return error.OutOfMemory,
        else => return err,
    };
    return output.toOwnedSlice();
}

fn writeJson(
    allocator: std.mem.Allocator,
    writer: *std.Io.Writer,
    value: std.json.Value,
    full_prompt: []const u8,
    user_prompt: []const u8,
) !void {
    switch (value) {
        .string => |text_value| {
            const safe = try sanitizeText(allocator, text_value, full_prompt, user_prompt);
            defer {
                std.crypto.secureZero(u8, safe);
                allocator.free(safe);
            }
            try std.json.Stringify.value(safe, .{}, writer);
        },
        .array => |array| {
            try writer.writeByte('[');
            for (array.items, 0..) |item, index| {
                if (index != 0) try writer.writeByte(',');
                try writeJson(allocator, writer, item, full_prompt, user_prompt);
            }
            try writer.writeByte(']');
        },
        .object => |object_value| {
            try writer.writeByte('{');
            var iterator = object_value.iterator();
            var first = true;
            while (iterator.next()) |entry| {
                if (!first) try writer.writeByte(',');
                first = false;

                try std.json.Stringify.value(entry.key_ptr.*, .{}, writer);
                try writer.writeByte(':');

                if (redact.isSensitiveKey(entry.key_ptr.*)) {
                    try std.json.Stringify.value(redact.marker, .{}, writer);
                } else {
                    try writeJson(allocator, writer, entry.value_ptr.*, full_prompt, user_prompt);
                }
            }
            try writer.writeByte('}');
        },
        else => try std.json.Stringify.value(value, .{}, writer),
    }
}

test "structured sanitization removes opaque values under sensitive keys" {
    const raw =
        \\{"type":"future.event","authorization":"opaque-auth-value","nested":[{"api_key":"opaque-api-value"},{"session-token":12345},{"vendor_secret":{"raw":"opaque-object-value"}}],"future_field":"kept"}
    ;
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, raw, .{
        .duplicate_field_behavior = .@"error",
    });
    defer parsed.deinit();

    const safe = try sanitizeJson(std.testing.allocator, parsed.value, "", "");
    defer std.testing.allocator.free(safe);

    for ([_][]const u8{ "opaque-auth-value", "opaque-api-value", "12345", "opaque-object-value" }) |secret| {
        try std.testing.expect(std.mem.indexOf(u8, safe, secret) == null);
    }
    try std.testing.expect(std.mem.indexOf(u8, safe, "future_field") != null);
    try std.testing.expect(std.mem.indexOf(u8, safe, "kept") != null);

    var reparsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, safe, .{
        .duplicate_field_behavior = .@"error",
    });
    defer reparsed.deinit();
    try std.testing.expectEqualStrings(redact.marker, reparsed.value.object.get("authorization").?.string);
    const nested = reparsed.value.object.get("nested").?.array.items;
    try std.testing.expectEqualStrings(redact.marker, nested[0].object.get("api_key").?.string);
    try std.testing.expectEqualStrings(redact.marker, nested[1].object.get("session-token").?.string);
    try std.testing.expectEqualStrings(redact.marker, nested[2].object.get("vendor_secret").?.string);
}

test "structured sanitization removes prompts and token patterns from values" {
    const full_prompt = "guarded private request";
    const user_prompt = "private request";
    const raw =
        \\{"message":"guarded private request and sk-secret-12345678901234567890","future_field":"visible-value"}
    ;
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, raw, .{
        .duplicate_field_behavior = .@"error",
    });
    defer parsed.deinit();

    const safe = try sanitizeJson(std.testing.allocator, parsed.value, full_prompt, user_prompt);
    defer std.testing.allocator.free(safe);
    try std.testing.expect(std.mem.indexOf(u8, safe, full_prompt) == null);
    try std.testing.expect(std.mem.indexOf(u8, safe, user_prompt) == null);
    try std.testing.expect(std.mem.indexOf(u8, safe, "sk-secret") == null);
    try std.testing.expect(std.mem.indexOf(u8, safe, "[PROMPT REDACTED]") != null);

    var reparsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, safe, .{
        .duplicate_field_behavior = .@"error",
    });
    defer reparsed.deinit();
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var parsed = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        "{\"authorization\":\"opaque-value\",\"message\":\"private prompt\"}",
        .{ .duplicate_field_behavior = .@"error" },
    );
    defer parsed.deinit();
    const safe = try sanitizeJson(allocator, parsed.value, "private prompt", "private prompt");
    defer allocator.free(safe);
}

test "structured sanitization propagates allocation failures without leaks" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationFailureCase, .{});
}

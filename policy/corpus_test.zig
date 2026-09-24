const std = @import("std");
const jevx = @import("jevx");

fn parseAction(text: []const u8) ?jevx.policy.ActionKind {
    inline for (@typeInfo(jevx.policy.ActionKind).@"enum".fields) |field| {
        if (std.mem.eql(u8, text, field.name)) return @enumFromInt(field.value);
    }
    return null;
}

fn assessment(action: jevx.policy.ActionKind) jevx.policy.Preflight {
    return .{
        .action = action,
        .route_confidence = 0.99,
        .impact_score = 0.01,
        .impact_confidence = 0.99,
        .destructive = 0,
        .credential_sensitive = 0,
        .external_side_effect = 0,
        .outside_workspace = 0,
        .underspecified = 0,
    };
}

test "hazardous holdout has zero autonomous approvals" {
    const corpus = @embedFile("corpus.jsonl");
    var lines = std.mem.splitScalar(u8, corpus, '\n');
    var hazardous: usize = 0;
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, line, .{});
        defer parsed.deinit();
        const object = parsed.value.object;
        const label = object.get("label").?.string;
        if (!std.mem.eql(u8, label, "hazardous-holdout")) continue;
        hazardous += 1;
        const action = parseAction(object.get("action").?.string) orelse return error.InvalidCorpusAction;
        try std.testing.expect(jevx.policy.evaluate(.aggressive, assessment(action), true).disposition != .auto_allow);
        try std.testing.expect(jevx.policy.evaluate(.aggressive, assessment(action), false).disposition != .auto_allow);
    }
    try std.testing.expect(hazardous >= 6);
}

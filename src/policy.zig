const std = @import("std");
const cli = @import("cli.zig");

pub const ActionKind = enum {
    read,
    edit,
    test_,
    format,
    install_project_local,
    commit_local,
    network,
    push,
    release,
    deploy,
    message,
    purchase,
    account_change,
    destructive,
    broad_destructive,
    privilege_change,
    credential_access,
    outside_workspace,
    sandbox_bypass,
    policy_tampering,
    credential_exfiltration,
    unknown,
};

pub const Preflight = struct {
    action: ActionKind,
    route_confidence: f64,
    impact_score: f64,
    impact_confidence: f64,
    destructive: f64,
    credential_sensitive: f64,
    external_side_effect: f64,
    outside_workspace: f64,
    underspecified: f64,
    jev_available: bool = true,
};

pub const Disposition = enum { auto_allow, require_confirmation, read_only_only, deny };

pub const Reason = enum {
    within_thresholds,
    always_confirm,
    hard_guard,
    low_route_confidence,
    high_impact,
    low_impact_confidence,
    hazard_signal,
    underspecified,
    jev_unavailable,
    noninteractive_confirmation,
    unsafe_resume,
    network_disabled,
};

pub const Evaluation = struct {
    disposition: Disposition,
    reason: Reason,
};

pub const GuardReason = enum {
    broad_destructive_command,
    credential_probe,
    credential_exfiltration,
    sandbox_bypass,
    policy_tampering,
};

pub const Thresholds = struct {
    route: f64,
    impact: f64,
    impact_confidence: f64,
    hazard: f64,
    underspecified: f64,

    pub fn forPolicy(name: cli.PolicyName) Thresholds {
        return switch (name) {
            .aggressive => .{ .route = 0.70, .impact = 1.5, .impact_confidence = 0.60, .hazard = 0.20, .underspecified = 0.35 },
            .balanced => .{ .route = 0.78, .impact = 1.25, .impact_confidence = 0.70, .hazard = 0.15, .underspecified = 0.25 },
            .conservative => .{ .route = 0.88, .impact = 0.75, .impact_confidence = 0.80, .hazard = 0.08, .underspecified = 0.15 },
        };
    }
};

pub fn tighten(user: cli.PolicyName, project: ?cli.PolicyName) cli.PolicyName {
    const candidate = project orelse return user;
    return if (@intFromEnum(candidate) > @intFromEnum(user)) candidate else user;
}

pub fn evaluate(profile: cli.PolicyName, input: Preflight, interactive: bool) Evaluation {
    if (isHardDenied(input.action)) return .{ .disposition = .deny, .reason = .hard_guard };

    if (!input.jev_available) {
        if (input.action == .read) return .{ .disposition = .read_only_only, .reason = .jev_unavailable };
        return .{ .disposition = .deny, .reason = .jev_unavailable };
    }

    if (alwaysConfirm(input.action)) return confirm(interactive, .always_confirm);

    const t = Thresholds.forPolicy(profile);
    if (!finiteProbability(input.route_confidence) or input.route_confidence < t.route)
        return confirm(interactive, .low_route_confidence);
    if (!std.math.isFinite(input.impact_score) or input.impact_score >= t.impact)
        return confirm(interactive, .high_impact);
    if (!finiteProbability(input.impact_confidence) or input.impact_confidence < t.impact_confidence)
        return confirm(interactive, .low_impact_confidence);
    if (hazardAtOrAbove(input, t.hazard)) return confirm(interactive, .hazard_signal);
    if (!finiteProbability(input.underspecified) or input.underspecified >= t.underspecified)
        return confirm(interactive, .underspecified);

    return .{ .disposition = .auto_allow, .reason = .within_thresholds };
}

fn confirm(interactive: bool, reason: Reason) Evaluation {
    return if (interactive)
        .{ .disposition = .require_confirmation, .reason = reason }
    else
        .{ .disposition = .deny, .reason = .noninteractive_confirmation };
}

fn finiteProbability(value: f64) bool {
    return std.math.isFinite(value) and value >= 0 and value <= 1;
}

fn hazardAtOrAbove(input: Preflight, threshold: f64) bool {
    return !finiteProbability(input.destructive) or input.destructive >= threshold or
        !finiteProbability(input.credential_sensitive) or input.credential_sensitive >= threshold or
        !finiteProbability(input.external_side_effect) or input.external_side_effect >= threshold or
        !finiteProbability(input.outside_workspace) or input.outside_workspace >= threshold;
}

pub fn isMutation(action: ActionKind) bool {
    return switch (action) {
        .read => false,
        else => true,
    };
}

pub fn isHardDenied(action: ActionKind) bool {
    return switch (action) {
        .credential_exfiltration, .sandbox_bypass, .policy_tampering, .broad_destructive => true,
        else => false,
    };
}

pub fn alwaysConfirm(action: ActionKind) bool {
    return switch (action) {
        .network, .push, .release, .deploy, .message, .purchase, .account_change, .destructive, .privilege_change, .credential_access, .outside_workspace, .unknown => true,
        else => false,
    };
}

/// Deterministic last-line defense for app-server approval payloads. Semantic
/// routing cannot override these literal guards.
pub fn guardText(text: []const u8) ?GuardReason {
    const patterns = [_]struct { text: []const u8, reason: GuardReason }{
        .{ .text = "rm -rf /", .reason = .broad_destructive_command },
        .{ .text = "rm -fr /", .reason = .broad_destructive_command },
        .{ .text = "rm -rf ~", .reason = .broad_destructive_command },
        .{ .text = "git reset --hard", .reason = .broad_destructive_command },
        .{ .text = "git clean -fd", .reason = .broad_destructive_command },
        .{ .text = "mkfs", .reason = .broad_destructive_command },
        .{ .text = "diskutil erase", .reason = .broad_destructive_command },
        .{ .text = "remove-item -recurse -force", .reason = .broad_destructive_command },
        .{ .text = "--dangerously-bypass-approvals-and-sandbox", .reason = .sandbox_bypass },
        .{ .text = "--sandbox danger-full-access", .reason = .sandbox_bypass },
        .{ .text = "security dump-keychain", .reason = .credential_probe },
        .{ .text = "security find-generic-password -w", .reason = .credential_probe },
        .{ .text = "secret-tool lookup", .reason = .credential_probe },
        .{ .text = "printenv", .reason = .credential_probe },
        .{ .text = ".ssh/id_", .reason = .credential_exfiltration },
        .{ .text = ".aws/credentials", .reason = .credential_exfiltration },
        .{ .text = ".config/gcloud/application_default_credentials.json", .reason = .credential_exfiltration },
        .{ .text = ".docker/config.json", .reason = .credential_exfiltration },
        .{ .text = ".netrc", .reason = .credential_exfiltration },
        .{ .text = ".config/jevx", .reason = .policy_tampering },
        .{ .text = ".jevx.json", .reason = .policy_tampering },
    };
    inline for (patterns) |entry| {
        if (indexOfIgnoreAsciiCase(text, entry.text) != null) return entry.reason;
    }
    return null;
}

fn indexOfIgnoreAsciiCase(haystack: []const u8, needle: []const u8) ?usize {
    if (needle.len == 0) return 0;
    if (needle.len > haystack.len) return null;
    var index: usize = 0;
    while (index + needle.len <= haystack.len) : (index += 1) {
        var matches = true;
        for (needle, 0..) |byte, offset| {
            if (std.ascii.toLower(haystack[index + offset]) != std.ascii.toLower(byte)) {
                matches = false;
                break;
            }
        }
        if (matches) return index;
    }
    return null;
}

fn safe(action: ActionKind) Preflight {
    return .{
        .action = action,
        .route_confidence = 0.95,
        .impact_score = 0.25,
        .impact_confidence = 0.9,
        .destructive = 0.01,
        .credential_sensitive = 0.01,
        .external_side_effect = 0.01,
        .outside_workspace = 0.01,
        .underspecified = 0.01,
    };
}

test "aggressive permits bounded workspace work" {
    inline for (.{ ActionKind.read, .edit, .test_, .format, .install_project_local, .commit_local }) |kind| {
        try std.testing.expectEqual(Disposition.auto_allow, evaluate(.aggressive, safe(kind), false).disposition);
    }
}

test "every hazardous holdout is never autonomously approved" {
    inline for (.{ ActionKind.push, .release, .deploy, .message, .purchase, .account_change, .destructive, .broad_destructive, .privilege_change, .credential_access, .outside_workspace, .sandbox_bypass, .policy_tampering, .credential_exfiltration }) |kind| {
        try std.testing.expect(evaluate(.aggressive, safe(kind), true).disposition != .auto_allow);
        try std.testing.expect(evaluate(.aggressive, safe(kind), false).disposition != .auto_allow);
    }
}

test "threshold boundaries fail closed" {
    var item = safe(.edit);
    item.route_confidence = 0.6999;
    try std.testing.expectEqual(Disposition.deny, evaluate(.aggressive, item, false).disposition);
    item = safe(.edit);
    item.impact_score = 1.5;
    try std.testing.expectEqual(Disposition.deny, evaluate(.aggressive, item, false).disposition);
    item = safe(.edit);
    item.destructive = 0.2;
    try std.testing.expectEqual(Disposition.deny, evaluate(.aggressive, item, false).disposition);
}

test "every policy decision branch has an explicit outcome" {
    var item = safe(.credential_exfiltration);
    try std.testing.expectEqual(Reason.hard_guard, evaluate(.aggressive, item, true).reason);

    item = safe(.read);
    item.jev_available = false;
    try std.testing.expectEqual(Disposition.read_only_only, evaluate(.aggressive, item, false).disposition);
    try std.testing.expectEqual(Reason.jev_unavailable, evaluate(.aggressive, item, false).reason);
    item.action = .edit;
    try std.testing.expectEqual(Disposition.deny, evaluate(.aggressive, item, true).disposition);

    item = safe(.push);
    try std.testing.expectEqual(Reason.always_confirm, evaluate(.aggressive, item, true).reason);
    try std.testing.expectEqual(Reason.noninteractive_confirmation, evaluate(.aggressive, item, false).reason);

    item = safe(.edit);
    item.route_confidence = 0.1;
    try std.testing.expectEqual(Reason.low_route_confidence, evaluate(.aggressive, item, true).reason);
    item = safe(.edit);
    item.impact_score = 2;
    try std.testing.expectEqual(Reason.high_impact, evaluate(.aggressive, item, true).reason);
    item = safe(.edit);
    item.impact_confidence = 0.1;
    try std.testing.expectEqual(Reason.low_impact_confidence, evaluate(.aggressive, item, true).reason);
    item = safe(.edit);
    item.outside_workspace = 0.9;
    try std.testing.expectEqual(Reason.hazard_signal, evaluate(.aggressive, item, true).reason);
    item = safe(.edit);
    item.underspecified = 0.9;
    try std.testing.expectEqual(Reason.underspecified, evaluate(.aggressive, item, true).reason);
    try std.testing.expectEqual(Reason.within_thresholds, evaluate(.aggressive, safe(.edit), false).reason);
}

test "project policy can tighten but not relax" {
    try std.testing.expectEqual(cli.PolicyName.conservative, tighten(.balanced, .conservative));
    try std.testing.expectEqual(cli.PolicyName.conservative, tighten(.conservative, .aggressive));
}

test "immutable command guard blocks broad destructive and bypass strings" {
    try std.testing.expectEqual(GuardReason.broad_destructive_command, guardText("rm -rf /Users/example"));
    try std.testing.expectEqual(GuardReason.sandbox_bypass, guardText("codex --dangerously-bypass-approvals-and-sandbox"));
    try std.testing.expectEqual(GuardReason.credential_exfiltration, guardText("show ~/.ssh/id_ed25519"));
    try std.testing.expectEqual(GuardReason.credential_probe, guardText("security find-generic-password -w service"));
    try std.testing.expectEqual(@as(?GuardReason, null), guardText("zig build test"));
}

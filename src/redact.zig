const std = @import("std");

pub const marker = "[REDACTED]";

/// Redacts structured JSON recursively. Values below credential-like keys are
/// replaced wholesale; strings elsewhere are passed through the text scanner.
/// The caller owns the returned slice.
pub fn redactJson(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, input, .{
        .duplicate_field_behavior = .@"error",
        .parse_numbers = false,
    });
    defer parsed.deinit();

    try redactValue(parsed.arena.allocator(), &parsed.value);

    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    std.json.Stringify.value(parsed.value, .{}, &output.writer) catch return error.OutOfMemory;
    return output.toOwnedSlice();
}

/// Redacts arbitrary text, including HTTP credential headers, common
/// key/value credentials, bearer tokens, API-key prefixes, and JWTs. The
/// caller owns the returned slice.
pub fn redactText(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);

    var line_start: usize = 0;
    var in_private_key = false;
    while (line_start < input.len) {
        const newline = std.mem.findScalarPos(u8, input, line_start, '\n') orelse input.len;
        var logical_end = newline;
        const had_cr = logical_end > line_start and input[logical_end - 1] == '\r';
        if (had_cr) logical_end -= 1;
        const line = input[line_start..logical_end];

        const starts_private_key = isPrivateKeyBoundary(line, "BEGIN");
        const ends_private_key = isPrivateKeyBoundary(line, "END");
        if (in_private_key or starts_private_key) {
            try output.appendSlice(allocator, marker);
            in_private_key = !ends_private_key;
        } else if (sensitiveHeaderColon(line)) |colon| {
            try output.appendSlice(allocator, line[0 .. colon + 1]);
            try output.appendSlice(allocator, " ");
            try output.appendSlice(allocator, marker);
        } else {
            try redactInline(allocator, &output, line);
        }

        if (had_cr) try output.append(allocator, '\r');
        if (newline < input.len) try output.append(allocator, '\n');
        line_start = if (newline < input.len) newline + 1 else input.len;
    }

    return output.toOwnedSlice(allocator);
}

/// Attempts recursive JSON redaction for objects/arrays and safely falls back
/// to the text scanner for all other input. This is the audit subsystem's
/// mandatory redaction entry point.
pub fn redact(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const trimmed = std.mem.trimStart(u8, input, " \t\r\n");
    if (trimmed.len != 0 and (trimmed[0] == '{' or trimmed[0] == '[')) {
        return redactJson(allocator, input) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => redactText(allocator, input),
        };
    }
    return redactText(allocator, input);
}

fn redactValue(allocator: std.mem.Allocator, value: *std.json.Value) !void {
    switch (value.*) {
        .object => |*object| {
            var iterator = object.iterator();
            while (iterator.next()) |entry| {
                if (isSensitiveKey(entry.key_ptr.*)) {
                    entry.value_ptr.* = .{ .string = marker };
                } else {
                    try redactValue(allocator, entry.value_ptr);
                }
            }
        },
        .array => |*array| {
            for (array.items) |*item| try redactValue(allocator, item);
        },
        .string => |text| {
            value.* = .{ .string = try redactText(allocator, text) };
        },
        else => {},
    }
}

fn sensitiveHeaderColon(line: []const u8) ?usize {
    const colon = std.mem.indexOfScalar(u8, line, ':') orelse return null;
    const name = std.mem.trim(u8, line[0..colon], " \t");
    if (isSensitiveKey(name)) return colon;
    return null;
}

const Assignment = struct {
    value_start: usize,
    value_end: usize,
    quote: ?u8,
};

fn redactInline(allocator: std.mem.Allocator, output: *std.ArrayList(u8), input: []const u8) !void {
    var cursor: usize = 0;
    var copied_to: usize = 0;
    while (cursor < input.len) {
        if (parseSensitiveAssignment(input, cursor)) |assignment| {
            try output.appendSlice(allocator, input[copied_to..assignment.value_start]);
            if (assignment.quote) |quote| try output.append(allocator, quote);
            try output.appendSlice(allocator, marker);
            if (assignment.quote) |quote| try output.append(allocator, quote);
            copied_to = assignment.value_end;
            cursor = assignment.value_end;
            continue;
        }

        if (urlPasswordEnd(input, cursor)) |end| {
            try output.appendSlice(allocator, input[copied_to .. cursor + 1]);
            try output.appendSlice(allocator, marker);
            copied_to = end;
            cursor = end;
            continue;
        }

        if (tokenEnd(input, cursor)) |end| {
            try output.appendSlice(allocator, input[copied_to..cursor]);
            try output.appendSlice(allocator, marker);
            copied_to = end;
            cursor = end;
            continue;
        }
        cursor += 1;
    }
    try output.appendSlice(allocator, input[copied_to..]);
}

fn parseSensitiveAssignment(input: []const u8, start: usize) ?Assignment {
    if (start > 0 and isKeyChar(input[start - 1])) return null;

    var key_start = start;
    var key_end: usize = undefined;
    var cursor = start;
    var key_quote: ?u8 = null;
    if (input[cursor] == '"' or input[cursor] == '\'') {
        key_quote = input[cursor];
        cursor += 1;
        key_start = cursor;
        while (cursor < input.len and input[cursor] != key_quote.?) : (cursor += 1) {}
        if (cursor == input.len) return null;
        key_end = cursor;
        cursor += 1;
    } else {
        while (cursor < input.len and isKeyChar(input[cursor]) and cursor - start <= 64) : (cursor += 1) {}
        if (cursor == start or cursor - start > 64) return null;
        key_end = cursor;
    }

    if (!isSensitiveKey(input[key_start..key_end])) return null;
    while (cursor < input.len and (input[cursor] == ' ' or input[cursor] == '\t')) : (cursor += 1) {}
    if (cursor == input.len or (input[cursor] != ':' and input[cursor] != '=')) return null;
    cursor += 1;
    while (cursor < input.len and (input[cursor] == ' ' or input[cursor] == '\t')) : (cursor += 1) {}

    const value_prefix_end = cursor;
    if (cursor == input.len) return .{ .value_start = value_prefix_end, .value_end = cursor, .quote = null };
    if (input[cursor] == '"' or input[cursor] == '\'') {
        const quote = input[cursor];
        const value_start = cursor;
        cursor += 1;
        var escaped = false;
        while (cursor < input.len) : (cursor += 1) {
            if (!escaped and input[cursor] == quote) {
                return .{ .value_start = value_start, .value_end = cursor + 1, .quote = quote };
            }
            if (!escaped and input[cursor] == '\\') {
                escaped = true;
            } else {
                escaped = false;
            }
        }
        return .{ .value_start = value_start, .value_end = cursor, .quote = quote };
    }

    while (cursor < input.len and input[cursor] != ',' and input[cursor] != ';' and
        input[cursor] != '&' and input[cursor] != '\r' and input[cursor] != '\n') : (cursor += 1)
    {}
    var value_end = cursor;
    while (value_end > value_prefix_end and (input[value_end - 1] == ' ' or input[value_end - 1] == '\t')) {
        value_end -= 1;
    }
    return .{ .value_start = value_prefix_end, .value_end = value_end, .quote = null };
}

fn tokenEnd(input: []const u8, start: usize) ?usize {
    if (start > 0 and isTokenChar(input[start - 1])) return null;

    if (startsWithIgnoreCase(input[start..], "bearer ")) {
        var end = start + "bearer ".len;
        while (end < input.len and isTokenChar(input[end])) : (end += 1) {}
        if (end - (start + "bearer ".len) >= 8) return end;
    }

    const prefixes = [_][]const u8{
        "sk-or-v1-", "sk-",      "github_pat_", "ghp_",     "gho_",    "ghu_",
        "ghs_",      "xoxb-",    "xoxp-",       "xoxa-",    "xapp-",   "AKIA",
        "ASIA",      "AIza",     "ya29.",       "hf_",      "glpat-",  "npm_",
        "pypi-",     "rk_live_", "sk_live_",    "sk_test_", "sq0atp-", "SG.",
    };
    inline for (prefixes) |prefix| {
        if (std.mem.startsWith(u8, input[start..], prefix)) {
            var end = start + prefix.len;
            while (end < input.len and isTokenChar(input[end])) : (end += 1) {}
            if (end - start >= prefix.len + 8) return end;
        }
    }

    if (std.mem.startsWith(u8, input[start..], "eyJ")) {
        var end = start;
        var dots: u8 = 0;
        while (end < input.len and isTokenChar(input[end])) : (end += 1) {
            if (input[end] == '.') dots += 1;
        }
        if (dots >= 2 and end - start >= 20) return end;
    }
    return null;
}

fn isSensitiveKey(raw: []const u8) bool {
    const key = std.mem.trim(u8, raw, " \t\r\n\"'");
    const sensitive = [_][]const u8{
        "authorization",   "proxyauthorization", "cookie",             "setcookie",
        "apikey",          "xapikey",            "password",           "passwd",
        "passphrase",      "token",              "accesstoken",        "refreshtoken",
        "idtoken",         "authtoken",          "secret",             "clientsecret",
        "credential",      "credentials",        "session",            "sessionid",
        "privatekey",      "openrouterapikey",   "accesskey",          "accesskeyid",
        "secretaccesskey", "awsaccesskeyid",     "awssecretaccesskey", "xauthtoken",
        "signature",       "sig",                "sas",                "sharedaccesssignature",
    };
    inline for (sensitive) |candidate| {
        if (canonicalEqual(key, candidate)) return true;
    }

    const sensitive_suffixes = [_][]const u8{
        "authorization", "cookie", "password",   "passwd",     "passphrase", "apikey",
        "token",         "secret", "credential", "privatekey", "accesskey",  "accesskeyid",
    };
    inline for (sensitive_suffixes) |suffix| {
        if (canonicalEndsWith(key, suffix)) return true;
    }
    return false;
}

fn canonicalEndsWith(raw: []const u8, suffix: []const u8) bool {
    const input = std.mem.trim(u8, raw, " \t\r\n\"'");
    var input_index = input.len;
    var suffix_index = suffix.len;
    while (suffix_index > 0) {
        while (input_index > 0 and isKeySeparator(input[input_index - 1])) input_index -= 1;
        while (suffix_index > 0 and isKeySeparator(suffix[suffix_index - 1])) suffix_index -= 1;
        if (suffix_index == 0) return true;
        if (input_index == 0) return false;
        input_index -= 1;
        suffix_index -= 1;
        if (std.ascii.toLower(input[input_index]) != std.ascii.toLower(suffix[suffix_index])) return false;
    }
    return true;
}

fn isPrivateKeyBoundary(line: []const u8, boundary: []const u8) bool {
    const marker_start = std.mem.indexOf(u8, line, "-----") orelse return false;
    const rest = line[marker_start + 5 ..];
    if (!std.mem.startsWith(u8, rest, boundary)) return false;
    return std.mem.indexOf(u8, rest[boundary.len..], "PRIVATE KEY-----") != null;
}

fn urlPasswordEnd(input: []const u8, colon: usize) ?usize {
    if (input[colon] != ':') return null;
    const scheme = std.mem.lastIndexOf(u8, input[0..colon], "://") orelse return null;
    const username_start = scheme + 3;
    if (username_start >= colon) return null;
    for (input[username_start..colon]) |byte| switch (byte) {
        '/', '?', '#', '@', ' ', '\t' => return null,
        else => {},
    };

    var end = colon + 1;
    while (end < input.len) : (end += 1) switch (input[end]) {
        '@' => return if (end > colon + 1) end else null,
        '/', '?', '#', ' ', '\t', '\r', '\n' => return null,
        else => {},
    };
    return null;
}

fn canonicalEqual(a: []const u8, b: []const u8) bool {
    var ai: usize = 0;
    var bi: usize = 0;
    while (true) {
        while (ai < a.len and isKeySeparator(a[ai])) : (ai += 1) {}
        while (bi < b.len and isKeySeparator(b[bi])) : (bi += 1) {}
        if (ai == a.len or bi == b.len) return ai == a.len and bi == b.len;
        if (std.ascii.toLower(a[ai]) != std.ascii.toLower(b[bi])) return false;
        ai += 1;
        bi += 1;
    }
}

fn startsWithIgnoreCase(haystack: []const u8, prefix: []const u8) bool {
    return haystack.len >= prefix.len and std.ascii.eqlIgnoreCase(haystack[0..prefix.len], prefix);
}

fn isKeySeparator(c: u8) bool {
    return c == '-' or c == '_' or c == '.' or c == ' ' or c == '\t';
}

fn isKeyChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_' or c == '-' or c == '.';
}

fn isTokenChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '+' or c == '/' or c == '=';
}

test "recursive JSON redaction covers nested credentials and tokens in strings" {
    const input =
        \\{"user":"alice","password":"hunter2","nested":{"api_key":"sk-or-v1-abcdefghijklmnopqrstuvwxyz","note":"Authorization: Bearer abcdefghijklmnop"},"items":[{"cookie":"sid=secret"}]}
    ;
    const result = try redact(std.testing.allocator, input);
    defer std.testing.allocator.free(result);

    try std.testing.expect(std.mem.indexOf(u8, result, "hunter2") == null);
    try std.testing.expect(std.mem.indexOf(u8, result, "sk-or-v1-") == null);
    try std.testing.expect(std.mem.indexOf(u8, result, "abcdefghijklmnop") == null);
    try std.testing.expect(std.mem.indexOf(u8, result, "sid=secret") == null);
    try std.testing.expect(std.mem.indexOf(u8, result, marker) != null);
}

test "text redaction covers headers assignments API keys and JWTs" {
    const input =
        "Authorization: Bearer topsecretvalue\r\n" ++
        "Cookie: sid=deadbeef\n" ++
        "password='do not print'; api_key=sk-abcdefghijklmnopqrstuvwxyz\n" ++
        "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signaturevalue";
    const result = try redactText(std.testing.allocator, input);
    defer std.testing.allocator.free(result);

    for ([_][]const u8{ "topsecretvalue", "deadbeef", "do not print", "sk-abcdefghijklmnopqrstuvwxyz", "eyJhbGci" }) |secret| {
        try std.testing.expect(std.mem.indexOf(u8, result, secret) == null);
    }
}

test "text redaction covers named custom tokens URLs and private keys" {
    const input =
        "db_password=database-secret\n" ++
        "vendor_token=hf_abcdefghijklmnopqrstuvwxyz\n" ++
        "https://alice:correct-horse@example.test/path\n" ++
        "-----BEGIN OPENSSH PRIVATE KEY-----\n" ++
        "unlabelled-private-key-material\n" ++
        "-----END OPENSSH PRIVATE KEY-----\n";
    const result = try redactText(std.testing.allocator, input);
    defer std.testing.allocator.free(result);

    for ([_][]const u8{ "database-secret", "hf_abcdefghijklmnopqrstuvwxyz", "correct-horse", "unlabelled-private-key-material" }) |secret| {
        try std.testing.expect(std.mem.indexOf(u8, result, secret) == null);
    }
    try std.testing.expect(std.mem.indexOf(u8, result, "alice:") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "example.test/path") != null);
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    const result = try redact(allocator, "{\"authorization\":\"Bearer very-secret-token\",\"ok\":true}");
    defer allocator.free(result);
}

test "redaction propagates allocation failures without leaks" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationFailureCase, .{});
}

const std = @import("std");

pub const default_port: u16 = 4768;
pub const max_header_bytes: usize = 16 * 1024;
pub const max_body_bytes: usize = 64 * 1024;
pub const request_read_timeout_seconds: i64 = 10;

pub const Handler = struct {
    context: *anyopaque,
    decide: *const fn (context: *anyopaque, allocator: std.mem.Allocator, prompt: []const u8, policy_name: []const u8) anyerror![]u8,
};

pub const Options = struct {
    port: u16,
    health_json: []const u8,
    pairing_token: []const u8,
};

pub const Listener = struct {
    server: std.Io.net.Server,
    port: u16,

    pub fn deinit(self: *Listener, io: std.Io) void {
        self.server.deinit(io);
        self.* = undefined;
    }
};

const Request = struct {
    method: []const u8,
    path: []const u8,
    origin: ?[]const u8,
    host: ?[]const u8,
    content_type: ?[]const u8,
    pairing_token: ?[]const u8,
    content_length: usize,
    body: []const u8,
};

const DecisionInput = struct {
    prompt: []const u8,
    policy: []const u8 = "aggressive",
};

/// Serves the browser companion on IPv4 loopback only. The server is
/// intentionally single-request-at-a-time: it exposes a decision primitive,
/// not a general remote agent or concurrent public API.
pub fn openListener(io: std.Io, preferred_port: u16) !Listener {
    const preferred = try std.Io.net.IpAddress.parseIp4("127.0.0.1", preferred_port);
    // An exclusive bind makes a second local process fail instead of sharing
    // this credential-backed endpoint through SO_REUSEPORT/SO_REUSEADDR. An
    // ephemeral fallback preserves immediate restart while the preferred port
    // is unavailable or in TIME_WAIT.
    const server = preferred.listen(io, .{}) catch |err| switch (err) {
        error.AddressInUse => blk: {
            const ephemeral = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 0);
            break :blk try ephemeral.listen(io, .{});
        },
        else => return err,
    };
    return .{ .port = server.socket.address.getPort(), .server = server };
}

pub fn serve(allocator: std.mem.Allocator, io: std.Io, listener: *Listener, options: Options, handler: Handler) !void {
    if (listener.port != options.port) return error.InvalidListenerPort;

    while (true) {
        var connection = try listener.server.accept(io);
        handleConnection(allocator, io, connection, options, handler) catch {
            // Do not return internal error details to the browser. A malformed
            // connection is isolated and the listener remains available.
            sendError(io, connection, 400, "bad_request", null) catch {};
            connection.close(io);
            continue;
        };
        connection.close(io);
    }
}

fn handleConnection(allocator: std.mem.Allocator, io: std.Io, stream: std.Io.net.Stream, options: Options, handler: Handler) !void {
    var receive_buffer: [4096]u8 = undefined;
    var network_reader = stream.reader(io, &receive_buffer);
    var bytes: [max_header_bytes + max_body_bytes]u8 = undefined;
    const request_bytes = try readRequestWithTimeout(io, &network_reader.interface, &bytes);
    const request = try parseRequest(request_bytes);

    if (!validHost(request.host, options.port)) {
        try sendError(io, stream, 403, "invalid_host", null);
        return;
    }
    if (request.origin) |origin| {
        if (!allowedOrigin(origin)) {
            try sendError(io, stream, 403, "origin_not_allowed", null);
            return;
        }
    }

    if (std.mem.eql(u8, request.method, "OPTIONS")) {
        const origin = request.origin orelse {
            try sendError(io, stream, 403, "origin_required", null);
            return;
        };
        try sendResponse(io, stream, 204, "application/json", "", origin);
        return;
    }

    if (!tokenMatches(options.pairing_token, request.pairing_token)) {
        try sendError(io, stream, 401, "pairing_required", request.origin);
        return;
    }

    if (std.mem.eql(u8, request.method, "GET") and std.mem.eql(u8, request.path, "/health")) {
        try sendResponse(io, stream, 200, "application/json", options.health_json, request.origin);
        return;
    }

    if (!std.mem.eql(u8, request.method, "POST") or !std.mem.eql(u8, request.path, "/v1/decide")) {
        try sendError(io, stream, 404, "not_found", request.origin);
        return;
    }
    const origin = request.origin orelse {
        try sendError(io, stream, 403, "origin_required", null);
        return;
    };
    if (request.content_type == null or !contentTypeIsJson(request.content_type.?)) {
        try sendError(io, stream, 415, "json_required", origin);
        return;
    }

    var parsed = std.json.parseFromSlice(DecisionInput, allocator, request.body, .{
        .duplicate_field_behavior = .@"error",
        .ignore_unknown_fields = false,
    }) catch {
        try sendError(io, stream, 400, "invalid_json", origin);
        return;
    };
    defer parsed.deinit();
    const prompt = std.mem.trim(u8, parsed.value.prompt, " \t\r\n");
    if (prompt.len == 0 or prompt.len > max_body_bytes) {
        try sendError(io, stream, 422, "invalid_prompt", origin);
        return;
    }

    const response = handler.decide(handler.context, allocator, prompt, parsed.value.policy) catch |err| switch (err) {
        error.InvalidConfig => {
            try sendError(io, stream, 400, "invalid_policy", origin);
            return;
        },
        else => {
            try sendError(io, stream, 503, "decision_unavailable", origin);
            return;
        },
    };
    defer allocator.free(response);
    try sendResponse(io, stream, 200, "application/json", response, origin);
}

const ReadRace = union(enum) {
    request: anyerror![]const u8,
    timeout: anyerror!void,
};

fn readRequestWithTimeout(io: std.Io, reader: *std.Io.Reader, buffer: []u8) ![]const u8 {
    var results: [2]ReadRace = undefined;
    var select: std.Io.Select(ReadRace) = .init(io, &results);
    defer select.cancelDiscard();
    select.async(.request, readRequestAsync, .{ reader, buffer });
    select.async(.timeout, requestReadDeadline, .{io});
    return switch (try select.await()) {
        .request => |result| try result,
        .timeout => |result| {
            try result;
            return error.RequestTimeout;
        },
    };
}

fn readRequestAsync(reader: *std.Io.Reader, buffer: []u8) anyerror![]const u8 {
    return readRequest(reader, buffer);
}

fn requestReadDeadline(io: std.Io) anyerror!void {
    return std.Io.sleep(io, .fromSeconds(request_read_timeout_seconds), .awake);
}

fn readRequest(reader: *std.Io.Reader, buffer: []u8) ![]const u8 {
    var used: usize = 0;
    var header_end: ?usize = null;
    var expected: ?usize = null;
    while (used < buffer.len) {
        var destination = [_][]u8{buffer[used..]};
        const count = reader.readVec(&destination) catch |err| switch (err) {
            error.EndOfStream => return error.TruncatedRequest,
            else => return err,
        };
        if (count == 0) return error.TruncatedRequest;
        used += count;

        if (header_end == null) {
            if (std.mem.indexOf(u8, buffer[0..used], "\r\n\r\n")) |index| {
                header_end = index + 4;
                if (header_end.? > max_header_bytes) return error.HeadersTooLarge;
                const head = buffer[0..header_end.?];
                const length = try contentLengthFromHead(head);
                if (length > max_body_bytes) return error.BodyTooLarge;
                expected = header_end.? + length;
                if (expected.? > buffer.len) return error.BodyTooLarge;
            } else if (used >= max_header_bytes) {
                return error.HeadersTooLarge;
            }
        }
        if (expected) |total| if (used >= total) return buffer[0..total];
    }
    return error.RequestTooLarge;
}

fn parseRequest(bytes: []const u8) !Request {
    const boundary = std.mem.indexOf(u8, bytes, "\r\n\r\n") orelse return error.TruncatedHeaders;
    const head = bytes[0..boundary];
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    const first = lines.next() orelse return error.MissingRequestLine;
    var request_line = std.mem.splitScalar(u8, first, ' ');
    const method = request_line.next() orelse return error.MissingMethod;
    const path = request_line.next() orelse return error.MissingPath;
    const version = request_line.next() orelse return error.MissingVersion;
    if (request_line.next() != null or !std.mem.eql(u8, version, "HTTP/1.1")) return error.InvalidRequestLine;

    var origin: ?[]const u8 = null;
    var host: ?[]const u8 = null;
    var content_type: ?[]const u8 = null;
    var pairing_token: ?[]const u8 = null;
    var content_length: ?usize = null;
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.InvalidHeader;
        const name = std.mem.trim(u8, line[0..colon], " \t");
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (hasUnsafeHeaderByte(value)) return error.InvalidHeader;
        if (std.ascii.eqlIgnoreCase(name, "origin")) {
            if (origin != null) return error.DuplicateHeader;
            origin = value;
        } else if (std.ascii.eqlIgnoreCase(name, "host")) {
            if (host != null) return error.DuplicateHeader;
            host = value;
        } else if (std.ascii.eqlIgnoreCase(name, "content-type")) {
            if (content_type != null) return error.DuplicateHeader;
            content_type = value;
        } else if (std.ascii.eqlIgnoreCase(name, "x-jevx-pairing-token")) {
            if (pairing_token != null) return error.DuplicateHeader;
            pairing_token = value;
        } else if (std.ascii.eqlIgnoreCase(name, "content-length")) {
            if (content_length != null) return error.DuplicateHeader;
            content_length = std.fmt.parseInt(usize, value, 10) catch return error.InvalidContentLength;
        } else if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) {
            // Chunked or compressed request bodies are unnecessary for this
            // bounded local API and complicate smuggling defenses.
            return error.UnsupportedTransferEncoding;
        }
    }
    const length = content_length orelse 0;
    const body_start = boundary + 4;
    if (length > max_body_bytes or body_start + length != bytes.len) return error.InvalidContentLength;
    return .{
        .method = method,
        .path = path,
        .origin = origin,
        .host = host,
        .content_type = content_type,
        .pairing_token = pairing_token,
        .content_length = length,
        .body = bytes[body_start..],
    };
}

fn contentLengthFromHead(head: []const u8) !usize {
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.next();
    var found: ?usize = null;
    while (lines.next()) |line| {
        if (line.len == 0) break;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.InvalidHeader;
        const name = std.mem.trim(u8, line[0..colon], " \t");
        if (!std.ascii.eqlIgnoreCase(name, "content-length")) continue;
        if (found != null) return error.DuplicateHeader;
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        found = std.fmt.parseInt(usize, value, 10) catch return error.InvalidContentLength;
    }
    return found orelse 0;
}

fn validHost(value: ?[]const u8, port: u16) bool {
    const host = value orelse return false;
    var expected: [64]u8 = undefined;
    const ipv4 = std.fmt.bufPrint(&expected, "127.0.0.1:{d}", .{port}) catch return false;
    if (std.mem.eql(u8, host, ipv4)) return true;
    const local = std.fmt.bufPrint(&expected, "localhost:{d}", .{port}) catch return false;
    return std.ascii.eqlIgnoreCase(host, local);
}

pub fn allowedOrigin(origin: []const u8) bool {
    if (std.mem.eql(u8, origin, "https://supratimsircar05.github.io")) return true;
    return localOrigin(origin, "http://127.0.0.1") or localOrigin(origin, "http://localhost");
}

fn localOrigin(origin: []const u8, prefix: []const u8) bool {
    if (std.mem.eql(u8, origin, prefix)) return true;
    if (!std.mem.startsWith(u8, origin, prefix) or origin.len <= prefix.len + 1 or origin[prefix.len] != ':') return false;
    for (origin[prefix.len + 1 ..]) |byte| if (!std.ascii.isDigit(byte)) return false;
    return true;
}

fn contentTypeIsJson(value: []const u8) bool {
    const semi = std.mem.indexOfScalar(u8, value, ';') orelse value.len;
    return std.ascii.eqlIgnoreCase(std.mem.trim(u8, value[0..semi], " \t"), "application/json");
}

fn hasUnsafeHeaderByte(value: []const u8) bool {
    for (value) |byte| if (byte == '\r' or byte == '\n' or byte == 0) return true;
    return false;
}

fn tokenMatches(expected: []const u8, actual: ?[]const u8) bool {
    const candidate = actual orelse return false;
    if (candidate.len != expected.len or expected.len == 0) return false;
    var difference: u8 = 0;
    for (expected, candidate) |left, right| difference |= left ^ right;
    return difference == 0;
}

fn sendError(io: std.Io, stream: std.Io.net.Stream, status: u16, code: []const u8, origin: ?[]const u8) !void {
    var body_buffer: [256]u8 = undefined;
    const body = try std.fmt.bufPrint(&body_buffer, "{{\"ok\":false,\"error\":\"{s}\"}}", .{code});
    try sendResponse(io, stream, status, "application/json", body, origin);
}

fn sendResponse(io: std.Io, stream: std.Io.net.Stream, status: u16, content_type: []const u8, body: []const u8, origin: ?[]const u8) !void {
    const reason = switch (status) {
        200 => "OK",
        204 => "No Content",
        401 => "Unauthorized",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Content",
        503 => "Service Unavailable",
        else => "Error",
    };
    var head_buffer: [2048]u8 = undefined;
    const head = if (origin) |allowed|
        try std.fmt.bufPrint(
            &head_buffer,
            "HTTP/1.1 {d} {s}\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nAccess-Control-Allow-Origin: {s}\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type, X-Jevx-Pairing-Token\r\nAccess-Control-Allow-Private-Network: true\r\nVary: Origin\r\nConnection: close\r\n\r\n",
            .{ status, reason, content_type, body.len, allowed },
        )
    else
        try std.fmt.bufPrint(
            &head_buffer,
            "HTTP/1.1 {d} {s}\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
            .{ status, reason, content_type, body.len },
        );
    var send_buffer: [4096]u8 = undefined;
    var network_writer = stream.writer(io, &send_buffer);
    try network_writer.interface.writeAll(head);
    if (body.len != 0) try network_writer.interface.writeAll(body);
    try network_writer.interface.flush();
}

test "origin allowlist is exact and loopback-only" {
    try std.testing.expect(allowedOrigin("https://supratimsircar05.github.io"));
    try std.testing.expect(allowedOrigin("http://localhost:8000"));
    try std.testing.expect(allowedOrigin("http://127.0.0.1:3000"));
    try std.testing.expect(!allowedOrigin("https://evil.example"));
    try std.testing.expect(!allowedOrigin("http://localhost.evil.example:8000"));
    try std.testing.expect(!allowedOrigin("https://supratimsircar05.github.io.evil.example"));
}

test "request parser bounds and extracts a browser decision" {
    const body = "{\"prompt\":\"inspect this repository\",\"policy\":\"balanced\"}";
    const raw = try std.fmt.allocPrint(
        std.testing.allocator,
        "POST /v1/decide HTTP/1.1\r\nHost: 127.0.0.1:4768\r\nOrigin: https://supratimsircar05.github.io\r\nContent-Type: application/json\r\nX-Jevx-Pairing-Token: 0123456789abcdef0123456789abcdef\r\nContent-Length: {d}\r\n\r\n{s}",
        .{ body.len, body },
    );
    defer std.testing.allocator.free(raw);
    const request = try parseRequest(raw);
    try std.testing.expectEqualStrings("POST", request.method);
    try std.testing.expectEqualStrings("/v1/decide", request.path);
    try std.testing.expectEqualStrings("0123456789abcdef0123456789abcdef", request.pairing_token.?);
    try std.testing.expectEqualStrings(body, request.body);
}

test "request parser rejects duplicate lengths and chunked bodies" {
    try std.testing.expectError(error.DuplicateHeader, parseRequest("POST /v1/decide HTTP/1.1\r\nHost: 127.0.0.1:4768\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n"));
    try std.testing.expectError(error.UnsupportedTransferEncoding, parseRequest("POST /v1/decide HTTP/1.1\r\nHost: 127.0.0.1:4768\r\nTransfer-Encoding: chunked\r\n\r\n"));
}

test "pairing tokens are required and compared exactly" {
    try std.testing.expect(tokenMatches("0123456789abcdef", "0123456789abcdef"));
    try std.testing.expect(!tokenMatches("0123456789abcdef", null));
    try std.testing.expect(!tokenMatches("0123456789abcdef", "0123456789abcdee"));
    try std.testing.expect(!tokenMatches("0123456789abcdef", "short"));
}

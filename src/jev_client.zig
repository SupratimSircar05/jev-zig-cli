const std = @import("std");
const decision = @import("decision.zig");

pub const max_api_key_bytes: usize = 4096;

pub const RetryPolicy = struct {
    max_attempts: u8 = 3,
    initial_backoff_ms: u64 = 500,
};

pub const Options = struct {
    adapter: decision.Adapter,
    max_request_bytes: usize = decision.default_max_request_bytes,
    max_response_bytes: usize = decision.default_max_response_bytes,
    connect_timeout_ms: u64 = 10_000,
    request_timeout_ms: u64 = 60_000,
    retry: RetryPolicy = .{},
};

pub const Result = struct {
    allocator: std.mem.Allocator,
    status: u16,
    body: []u8,
    resolved_model: ?[]u8,

    pub fn deinit(self: *Result) void {
        self.allocator.free(self.body);
        if (self.resolved_model) |model| self.allocator.free(model);
        self.* = undefined;
    }

    pub fn isSuccess(self: Result) bool {
        return self.status >= 200 and self.status < 300;
    }
};

pub const CircuitBreaker = struct {
    consecutive_transient_failures: u8 = 0,
    open_until_ms: i64 = 0,

    pub const failure_threshold: u8 = 3;
    pub const open_duration_ms: i64 = 60_000;

    pub fn permit(self: *CircuitBreaker, now_ms: i64) bool {
        if (self.open_until_ms == 0) return true;
        if (now_ms < self.open_until_ms) return false;
        self.consecutive_transient_failures = 0;
        self.open_until_ms = 0;
        return true;
    }

    pub fn recordSuccess(self: *CircuitBreaker) void {
        self.consecutive_transient_failures = 0;
        self.open_until_ms = 0;
    }

    pub fn recordTransientFailure(self: *CircuitBreaker, now_ms: i64) void {
        self.consecutive_transient_failures +|= 1;
        if (self.consecutive_transient_failures >= failure_threshold) {
            self.open_until_ms = now_ms +| open_duration_ms;
        }
    }
};

pub const Client = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    options: Options,
    circuit: CircuitBreaker = .{},

    pub fn init(allocator: std.mem.Allocator, io: std.Io, options: Options) Client {
        return .{ .allocator = allocator, .io = io, .options = options };
    }

    /// Sends one logical decision request. Only explicit transient HTTP
    /// statuses are retried. Transport failures are never retried because a
    /// POST may already have reached the provider.
    pub fn decide(self: *Client, body: []u8, api_key: []const u8) !Result {
        try validateApiKey(api_key);
        if (self.options.connect_timeout_ms == 0 or self.options.request_timeout_ms == 0)
            return error.InvalidTimeout;
        var request_validation = decision.validateRequest(
            self.allocator,
            body,
            self.options.max_request_bytes,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidDecisionRequest,
        };
        defer request_validation.deinit();

        const now = realMillis(self.io);
        if (!self.circuit.permit(now)) return error.CircuitOpen;

        var http_client: std.http.Client = .{ .allocator = self.allocator, .io = self.io };
        defer http_client.deinit();

        const attempts = @max(@as(u8, 1), self.options.retry.max_attempts);
        var attempt: u8 = 0;
        while (attempt < attempts) : (attempt += 1) {
            const wire = sendOnce(
                self.allocator,
                &http_client,
                self.options.adapter.endpoint(),
                body,
                api_key,
                self.options.max_response_bytes,
                self.options.connect_timeout_ms,
                self.options.request_timeout_ms,
            ) catch |err| {
                // A timeout/read/write failure after send is ambiguous. Count
                // it for circuit health, but never replay the POST.
                if (err == error.AmbiguousPostSendFailure or
                    err == error.TransportFailureBeforeSend or
                    err == error.TransportTimeoutBeforeSend)
                {
                    self.circuit.recordTransientFailure(realMillis(self.io));
                }
                return err;
            };

            const status = wire.status;
            if (status >= 200 and status < 300) {
                var validated = decision.validateResponse(
                    self.allocator,
                    wire.body,
                    self.options.max_response_bytes,
                ) catch |err| {
                    self.allocator.free(wire.body);
                    return switch (err) {
                        error.OutOfMemory => error.OutOfMemory,
                        else => error.InvalidProviderResponse,
                    };
                };
                defer validated.deinit();
                const resolved_model = try self.allocator.dupe(u8, validated.resolved_model);
                self.circuit.recordSuccess();
                return .{
                    .allocator = self.allocator,
                    .status = status,
                    .body = wire.body,
                    .resolved_model = resolved_model,
                };
            }

            if (!isRetryableStatus(status)) {
                self.circuit.recordSuccess();
                return .{
                    .allocator = self.allocator,
                    .status = status,
                    .body = wire.body,
                    .resolved_model = null,
                };
            }

            self.circuit.recordTransientFailure(realMillis(self.io));
            const can_try_again = attempt + 1 < attempts and self.circuit.permit(realMillis(self.io));
            if (!can_try_again) {
                return .{
                    .allocator = self.allocator,
                    .status = status,
                    .body = wire.body,
                    .resolved_model = null,
                };
            }

            const delay_ms = wire.retry_after_ms orelse exponentialBackoff(
                self.options.retry.initial_backoff_ms,
                attempt,
            );
            // A Retry-After beyond the configured request deadline is honored
            // by returning the response instead of replaying the POST early or
            // blocking this one-shot CLI indefinitely.
            if (delay_ms > self.options.request_timeout_ms) {
                return .{
                    .allocator = self.allocator,
                    .status = status,
                    .body = wire.body,
                    .resolved_model = null,
                };
            }
            self.allocator.free(wire.body);
            try std.Io.sleep(self.io, .fromMilliseconds(safeI64(delay_ms)), .awake);
        }
        unreachable;
    }
};

const WireResponse = struct {
    status: u16,
    body: []u8,
    retry_after_ms: ?u64,
};

fn sendOnce(
    allocator: std.mem.Allocator,
    http_client: *std.http.Client,
    endpoint: []const u8,
    body: []u8,
    api_key: []const u8,
    max_response_bytes: usize,
    connect_timeout_ms: u64,
    request_timeout_ms: u64,
) !WireResponse {
    const uri = std.Uri.parse(endpoint) catch return error.InvalidEndpoint;
    const authorization = try std.fmt.allocPrint(allocator, "Bearer {s}", .{api_key});
    defer {
        std.crypto.secureZero(u8, authorization);
        allocator.free(authorization);
    }

    const accept_header = std.http.Header{ .name = "accept", .value = "application/json" };
    const options = std.http.Client.RequestOptions{
        .redirect_behavior = .unhandled,
        .headers = .{
            .authorization = .{ .override = authorization },
            .content_type = .{ .override = "application/json" },
            .accept_encoding = .omit,
            .user_agent = .{ .override = "jev-zig-cli/0.1" },
        },
        .extra_headers = &.{accept_header},
    };
    var request = try openRequestWithTimeout(
        http_client,
        uri,
        options,
        connect_timeout_ms,
    );
    defer request.deinit();

    return exchangeWithTimeout(
        allocator,
        &request,
        body,
        max_response_bytes,
        request_timeout_ms,
    );
}

fn exchange(
    allocator: std.mem.Allocator,
    request: *std.http.Client.Request,
    body: []u8,
    max_response_bytes: usize,
) !WireResponse {
    request.sendBodyComplete(body) catch return error.AmbiguousPostSendFailure;
    var response = request.receiveHead(&.{}) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return error.AmbiguousPostSendFailure,
    };
    const status: u16 = @intCast(@intFromEnum(response.head.status));
    const retry_after_ms = retryAfterFromHead(response.head, realMillis(request.client.io));

    var transfer_buffer: [16 * 1024]u8 = undefined;
    const reader = response.reader(&transfer_buffer);
    const response_body = reader.allocRemaining(allocator, .limited(max_response_bytes)) catch |err| switch (err) {
        error.StreamTooLong => return error.ResponseTooLarge,
        else => return error.AmbiguousPostSendFailure,
    };

    return .{ .status = status, .body = response_body, .retry_after_ms = retry_after_ms };
}

fn openRequest(
    http_client: *std.http.Client,
    uri: std.Uri,
    options: std.http.Client.RequestOptions,
) !std.http.Client.Request {
    return http_client.request(.POST, uri, options);
}

const RequestRace = union(enum) {
    operation: anyerror!std.http.Client.Request,
    timer: std.Io.Cancelable!void,
};

fn openRequestWithTimeout(
    http_client: *std.http.Client,
    uri: std.Uri,
    options: std.http.Client.RequestOptions,
    timeout_ms: u64,
) !std.http.Client.Request {
    const timeout = try timeoutFromMilliseconds(http_client.io, timeout_ms);
    var buffer: [2]RequestRace = undefined;
    var select = std.Io.Select(RequestRace).init(http_client.io, &buffer);
    select.async(.operation, openRequest, .{ http_client, uri, options });
    select.async(.timer, std.Io.Timeout.sleep, .{ timeout, http_client.io });

    const first = select.await() catch |err| {
        drainRequestRace(&select);
        return err;
    };
    switch (first) {
        .operation => |result| {
            select.cancelDiscard();
            return result catch |err| switch (err) {
                error.Canceled => error.TransportFailureBeforeSend,
                else => error.TransportFailureBeforeSend,
            };
        },
        .timer => |result| {
            drainRequestRace(&select);
            result catch |err| return err;
            return error.TransportTimeoutBeforeSend;
        },
    }
}

fn drainRequestRace(select: *std.Io.Select(RequestRace)) void {
    while (select.cancel()) |late| switch (late) {
        .operation => |result| {
            if (result) |request_value| {
                var request = request_value;
                request.deinit();
            } else |_| {}
        },
        .timer => {},
    };
}

const ExchangeRace = union(enum) {
    operation: anyerror!WireResponse,
    timer: std.Io.Cancelable!void,
};

fn exchangeWithTimeout(
    allocator: std.mem.Allocator,
    request: *std.http.Client.Request,
    body: []u8,
    max_response_bytes: usize,
    timeout_ms: u64,
) !WireResponse {
    const io = request.client.io;
    const timeout = try timeoutFromMilliseconds(io, timeout_ms);
    var buffer: [2]ExchangeRace = undefined;
    var select = std.Io.Select(ExchangeRace).init(io, &buffer);
    select.async(.operation, exchange, .{ allocator, request, body, max_response_bytes });
    select.async(.timer, std.Io.Timeout.sleep, .{ timeout, io });

    const first = select.await() catch |err| {
        drainExchangeRace(allocator, &select);
        return err;
    };
    switch (first) {
        .operation => |result| {
            select.cancelDiscard();
            return result catch |err| switch (err) {
                error.Canceled => error.AmbiguousPostSendFailure,
                else => |other| other,
            };
        },
        .timer => |result| {
            drainExchangeRace(allocator, &select);
            result catch |err| return err;
            return error.AmbiguousPostSendFailure;
        },
    }
}

fn drainExchangeRace(allocator: std.mem.Allocator, select: *std.Io.Select(ExchangeRace)) void {
    while (select.cancel()) |late| switch (late) {
        .operation => |result| {
            if (result) |wire| allocator.free(wire.body) else |_| {}
        },
        .timer => {},
    };
}

fn timeoutFromMilliseconds(io: std.Io, timeout_ms: u64) !std.Io.Timeout {
    const millis = std.math.cast(i64, timeout_ms) orelse return error.InvalidTimeout;
    return .{ .deadline = .fromNow(io, .{
        .raw = std.Io.Duration.fromMilliseconds(millis),
        .clock = .awake,
    }) };
}

/// Rejects control characters and header delimiters before a credential can be
/// copied into an HTTP header. OpenRouter keys are printable ASCII tokens.
pub fn validateApiKey(api_key: []const u8) !void {
    if (api_key.len == 0) return error.MissingApiKey;
    if (api_key.len > max_api_key_bytes) return error.ApiKeyTooLong;
    for (api_key) |byte| {
        if (byte < 0x21 or byte > 0x7e) return error.InvalidApiKey;
    }
}

pub fn isRetryableStatus(status: u16) bool {
    return switch (status) {
        429, 500, 502, 503, 524, 529 => true,
        else => false,
    };
}

fn exponentialBackoff(initial_ms: u64, completed_attempt: u8) u64 {
    const shift: u6 = @intCast(@min(completed_attempt, 20));
    return initial_ms << shift;
}

fn safeI64(value: u64) i64 {
    return @intCast(@min(value, @as(u64, @intCast(std.math.maxInt(i64)))));
}

fn realMillis(io: std.Io) i64 {
    return std.Io.Clock.real.now(io).toMilliseconds();
}

fn retryAfterFromHead(head: std.http.Client.Response.Head, now_epoch_ms: i64) ?u64 {
    var iterator = head.iterateHeaders();
    while (iterator.next()) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "retry-after")) {
            return parseRetryAfter(header.value, now_epoch_ms);
        }
    }
    return null;
}

/// Parses both RFC 9110 Retry-After forms: delta-seconds and IMF-fixdate.
pub fn parseRetryAfter(value: []const u8, now_epoch_ms: i64) ?u64 {
    const text = std.mem.trim(u8, value, " \t");
    if (std.fmt.parseInt(u64, text, 10)) |seconds| {
        return std.math.mul(u64, seconds, 1000) catch std.math.maxInt(u64);
    } else |_| {}

    const deadline_seconds = parseImfFixdate(text) orelse return null;
    const now_seconds = @divFloor(now_epoch_ms, 1000);
    if (deadline_seconds <= now_seconds) return 0;
    return @intCast((deadline_seconds - now_seconds) * 1000);
}

fn parseImfFixdate(text: []const u8) ?i64 {
    // Sun, 06 Nov 1994 08:49:37 GMT
    if (text.len != 29) return null;
    if (text[3] != ',' or text[4] != ' ' or text[7] != ' ' or
        text[11] != ' ' or text[16] != ' ' or text[19] != ':' or
        text[22] != ':' or text[25] != ' ' or
        !std.mem.eql(u8, text[26..29], "GMT")) return null;

    const day = std.fmt.parseInt(u8, text[5..7], 10) catch return null;
    const year = std.fmt.parseInt(u16, text[12..16], 10) catch return null;
    const hour = std.fmt.parseInt(u8, text[17..19], 10) catch return null;
    const minute = std.fmt.parseInt(u8, text[20..22], 10) catch return null;
    const second = std.fmt.parseInt(u8, text[23..25], 10) catch return null;
    const month = parseMonth(text[8..11]) orelse return null;
    if (year < 1970 or day == 0 or day > daysInMonth(year, month) or
        hour > 23 or minute > 59 or second > 59) return null;

    var days: i64 = 0;
    var cursor_year: u16 = 1970;
    while (cursor_year < year) : (cursor_year += 1) {
        days += if (isLeapYear(cursor_year)) 366 else 365;
    }
    var cursor_month: u8 = 1;
    while (cursor_month < month) : (cursor_month += 1) {
        days += daysInMonth(year, cursor_month);
    }
    days += day - 1;
    return days * 86_400 + @as(i64, hour) * 3600 + @as(i64, minute) * 60 + second;
}

fn parseMonth(text: []const u8) ?u8 {
    const names = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    for (names, 1..) |name, number| {
        if (std.mem.eql(u8, text, name)) return @intCast(number);
    }
    return null;
}

fn isLeapYear(year: u16) bool {
    return @mod(year, 4) == 0 and (@mod(year, 100) != 0 or @mod(year, 400) == 0);
}

fn daysInMonth(year: u16, month: u8) u8 {
    return switch (month) {
        1, 3, 5, 7, 8, 10, 12 => 31,
        4, 6, 9, 11 => 30,
        2 => if (isLeapYear(year)) 29 else 28,
        else => 0,
    };
}

test "retry allowlist excludes ambiguous and permanent statuses" {
    inline for ([_]u16{ 429, 500, 502, 503, 524, 529 }) |status| {
        try std.testing.expect(isRetryableStatus(status));
    }
    inline for ([_]u16{ 400, 401, 402, 403, 404, 408, 413, 501, 504 }) |status| {
        try std.testing.expect(!isRetryableStatus(status));
    }
}

test "Retry-After delta seconds and dates are honored" {
    try std.testing.expectEqual(@as(?u64, 7000), parseRetryAfter("7", 0));
    const deadline = parseImfFixdate("Sun, 06 Nov 1994 08:49:37 GMT").?;
    try std.testing.expectEqual(@as(?u64, 5000), parseRetryAfter(
        "Sun, 06 Nov 1994 08:49:37 GMT",
        (deadline - 5) * 1000,
    ));
    try std.testing.expectEqual(@as(?u64, 0), parseRetryAfter(
        "Sun, 06 Nov 1994 08:49:37 GMT",
        deadline * 1000,
    ));
    try std.testing.expectEqual(@as(?u64, null), parseRetryAfter("tomorrow", 0));
}

test "circuit opens for sixty seconds after three transient failures" {
    var circuit: CircuitBreaker = .{};
    try std.testing.expect(circuit.permit(1000));
    circuit.recordTransientFailure(1000);
    circuit.recordTransientFailure(1001);
    try std.testing.expect(circuit.permit(1002));
    circuit.recordTransientFailure(1002);
    try std.testing.expect(!circuit.permit(61_001));
    try std.testing.expect(circuit.permit(61_002));
    try std.testing.expectEqual(@as(u8, 0), circuit.consecutive_transient_failures);
}

test "success resets circuit state" {
    var circuit: CircuitBreaker = .{};
    circuit.recordTransientFailure(0);
    circuit.recordTransientFailure(1);
    circuit.recordSuccess();
    try std.testing.expectEqual(@as(u8, 0), circuit.consecutive_transient_failures);
    try std.testing.expectEqual(@as(i64, 0), circuit.open_until_ms);
}

test "API keys are visible ASCII and bounded before header construction" {
    try validateApiKey("sk-or-v1-test_token.123");
    try std.testing.expectError(error.MissingApiKey, validateApiKey(""));
    try std.testing.expectError(error.InvalidApiKey, validateApiKey("bad\r\nX-Injected: yes"));
    try std.testing.expectError(error.InvalidApiKey, validateApiKey("has space"));

    const oversized = try std.testing.allocator.alloc(u8, max_api_key_bytes + 1);
    defer std.testing.allocator.free(oversized);
    @memset(oversized, 'a');
    try std.testing.expectError(error.ApiKeyTooLong, validateApiKey(oversized));
}

test "post-send request deadline is ambiguous and never replayed" {
    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try listen_address.listen(std.testing.io, .{});
    defer server.deinit(std.testing.io);
    var server_task = std.testing.io.async(acceptAndHold, .{ &server, std.testing.io });
    defer _ = server_task.cancel(std.testing.io) catch {};

    var endpoint_buffer: [128]u8 = undefined;
    const endpoint = try std.fmt.bufPrint(
        &endpoint_buffer,
        "http://127.0.0.1:{d}/decisions",
        .{server.socket.address.getPort()},
    );
    var http_client: std.http.Client = .{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
    };
    defer http_client.deinit();
    var body = [_]u8{ '{', '}' };
    try std.testing.expectError(
        error.AmbiguousPostSendFailure,
        sendOnce(
            std.testing.allocator,
            &http_client,
            endpoint,
            &body,
            "test-key",
            1024,
            1000,
            20,
        ),
    );
}

fn acceptAndHold(server: *std.Io.net.Server, io: std.Io) !void {
    var stream = try server.accept(io);
    defer stream.close(io);
    try std.Io.sleep(io, .fromMilliseconds(500), .awake);
}

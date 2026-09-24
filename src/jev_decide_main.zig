const std = @import("std");
const builtin = @import("builtin");
const decision = @import("decision.zig");
const exit_codes = @import("exit_codes.zig");
const jev = @import("jev_client.zig");

const config_limit: usize = 64 * 1024;
const circuit_state_limit: usize = 4096;
const max_connect_timeout_seconds: usize = 300;
const max_request_timeout_seconds: usize = 3600;

const Config = struct {
    allocator: std.mem.Allocator,
    adapter: decision.Adapter = .alpha_decisions,
    model: ?[]u8 = null,
    keychain_service: []u8,
    keychain_account: ?[]u8 = null,
    max_request_bytes: usize = decision.default_max_request_bytes,
    max_response_bytes: usize = decision.default_max_response_bytes,
    max_attempts: u8 = 3,
    connect_timeout_ms: u64 = 10_000,
    request_timeout_ms: u64 = 60_000,
    loaded: bool = false,

    fn defaults(allocator: std.mem.Allocator) !Config {
        const model = try allocator.dupe(u8, decision.default_model);
        errdefer allocator.free(model);
        const service = try allocator.dupe(u8, "jev-openrouter");
        errdefer allocator.free(service);
        const account = try allocator.dupe(u8, "default");
        return .{
            .allocator = allocator,
            .model = model,
            .keychain_service = service,
            .keychain_account = account,
        };
    }

    fn deinit(self: *Config) void {
        if (self.model) |value| self.allocator.free(value);
        self.allocator.free(self.keychain_service);
        if (self.keychain_account) |value| self.allocator.free(value);
        self.* = undefined;
    }
};

const CircuitStateWire = struct {
    version: u8,
    consecutive_transient_failures: u8,
    open_until_epoch_ms: i64,
};

/// The file remains exclusively locked for the lifetime of a decision call so
/// concurrent CLI processes cannot lose failure increments. It contains only
/// a version, a bounded counter, and an epoch-millisecond expiry.
const CircuitStore = struct {
    io: std.Io,
    dir: std.Io.Dir,
    file: std.Io.File,
    owns_dir: bool,

    fn openOwned(io: std.Io, dir: std.Io.Dir, name: []const u8) !CircuitStore {
        errdefer dir.close(io);
        return .{
            .io = io,
            .dir = dir,
            .file = try openCircuitFile(dir, io, name),
            .owns_dir = true,
        };
    }

    fn openBorrowed(io: std.Io, dir: std.Io.Dir, name: []const u8) !CircuitStore {
        return .{
            .io = io,
            .dir = dir,
            .file = try openCircuitFile(dir, io, name),
            .owns_dir = false,
        };
    }

    fn deinit(self: *CircuitStore) void {
        self.file.close(self.io);
        if (self.owns_dir) self.dir.close(self.io);
        self.* = undefined;
    }

    fn load(self: *CircuitStore, allocator: std.mem.Allocator) !jev.CircuitBreaker {
        const byte_count_u64 = try self.file.length(self.io);
        if (byte_count_u64 == 0) return .{};
        const byte_count = std.math.cast(usize, byte_count_u64) orelse return error.InvalidCircuitState;
        if (byte_count > circuit_state_limit) return error.InvalidCircuitState;
        const bytes = try allocator.alloc(u8, byte_count);
        defer allocator.free(bytes);
        if (try self.file.readPositionalAll(self.io, bytes, 0) != bytes.len)
            return error.InvalidCircuitState;
        return parseCircuitState(allocator, bytes);
    }

    fn save(self: *CircuitStore, allocator: std.mem.Allocator, state: jev.CircuitBreaker) !void {
        const wire = CircuitStateWire{
            .version = 1,
            .consecutive_transient_failures = state.consecutive_transient_failures,
            .open_until_epoch_ms = state.open_until_ms,
        };
        const bytes = try std.json.Stringify.valueAlloc(allocator, wire, .{});
        defer allocator.free(bytes);
        if (bytes.len > circuit_state_limit) return error.InvalidCircuitState;
        try self.file.setLength(self.io, 0);
        try self.file.writePositionalAll(self.io, bytes, 0);
        try self.file.sync(self.io);
    }
};

const Secret = struct {
    allocator: std.mem.Allocator,
    bytes: []u8,
    source: enum { environment, keychain, credential_manager },

    fn deinit(self: *Secret) void {
        std.crypto.secureZero(u8, self.bytes);
        self.allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub fn main(init: std.process.Init) !void {
    run(init) catch |err| {
        var buffer: [1024]u8 = undefined;
        var stderr_writer = std.Io.File.stderr().writer(init.io, &buffer);
        const stderr = &stderr_writer.interface;
        stderr.print("jev-decide: {s}\n", .{@errorName(err)}) catch {};
        stderr.flush() catch {};
        std.process.exit(exitCode(err));
    };
}

fn run(init: std.process.Init) !void {
    const allocator = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    var stdout_buffer: [16 * 1024]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(init.io, &stdout_buffer);
    const stdout = &stdout_writer.interface;
    var stderr_buffer: [4 * 1024]u8 = undefined;
    var stderr_writer = std.Io.File.stderr().writer(init.io, &stderr_buffer);
    const stderr = &stderr_writer.interface;

    var config = try loadConfig(allocator, init.io, init.environ_map);
    defer config.deinit();

    var health = false;
    var store_key = false;
    var adapter_override: ?decision.Adapter = null;
    var model_override: ?[]const u8 = null;
    var index: usize = 1;
    while (index < args.len) : (index += 1) {
        const arg = args[index];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            try printHelp(stdout);
            try stdout.flush();
            return;
        } else if (std.mem.eql(u8, arg, "--health")) {
            health = true;
        } else if (std.mem.eql(u8, arg, "--store-key")) {
            store_key = true;
        } else if (std.mem.eql(u8, arg, "--adapter")) {
            index += 1;
            if (index >= args.len) return error.MissingAdapterValue;
            adapter_override = try decision.Adapter.parse(args[index]);
        } else if (std.mem.eql(u8, arg, "--model")) {
            index += 1;
            if (index >= args.len or args[index].len == 0) return error.MissingModelValue;
            model_override = args[index];
        } else {
            return error.UnknownArgument;
        }
    }

    const adapter = adapter_override orelse config.adapter;
    if (health and store_key) return error.ConflictingModes;
    if (store_key) {
        var stdin_buffer: [4096]u8 = undefined;
        var stdin_reader = std.Io.File.stdin().readerStreaming(init.io, &stdin_buffer);
        const input = stdin_reader.interface.allocRemaining(
            allocator,
            .limited(jev.max_api_key_bytes + 2),
        ) catch |err| switch (err) {
            error.StreamTooLong => return error.ApiKeyTooLong,
            else => return err,
        };
        defer {
            std.crypto.secureZero(u8, input);
            allocator.free(input);
        }
        const key = std.mem.trimEnd(u8, input, "\r\n");
        try jev.validateApiKey(key);
        try storeCredential(
            allocator,
            config.keychain_service,
            config.keychain_account orelse return error.InvalidKeychainConfig,
            key,
        );
        try stdout.writeAll("{\"ok\":true,\"credential_stored\":true}\n");
        try stdout.flush();
        return;
    }
    var secret = try loadSecret(
        allocator,
        init.environ_map,
        config.keychain_service,
        config.keychain_account,
    );
    defer secret.deinit();

    if (health) {
        try stdout.print(
            "{{\"ok\":true,\"adapter\":\"{s}\",\"endpoint\":\"{s}\",\"config_loaded\":{},\"credential_source\":\"{s}\"}}\n",
            .{
                adapter.name(),
                adapter.endpoint(),
                config.loaded,
                switch (secret.source) {
                    .environment => "environment",
                    .keychain => "keychain",
                    .credential_manager => "credential_manager",
                },
            },
        );
        try stdout.flush();
        return;
    }

    var circuit_store = try openCircuitStore(allocator, init.io, init.environ_map, adapter);
    defer circuit_store.deinit();
    var persisted_circuit = circuit_store.load(allocator) catch |err| switch (err) {
        error.InvalidCircuitState => state: {
            try stderr.writeAll("jev-decide: ignoring invalid circuit state\n");
            try stderr.flush();
            break :state jev.CircuitBreaker{};
        },
        else => return err,
    };

    var stdin_buffer: [16 * 1024]u8 = undefined;
    var stdin_reader = std.Io.File.stdin().readerStreaming(init.io, &stdin_buffer);
    const input = stdin_reader.interface.allocRemaining(
        allocator,
        .limited(config.max_request_bytes),
    ) catch |err| switch (err) {
        error.StreamTooLong => return error.BodyTooLarge,
        else => return err,
    };
    defer allocator.free(input);

    const default_model = model_override orelse config.model;
    const request_body = try prepareRequest(
        allocator,
        input,
        default_model,
        config.max_request_bytes,
    );
    defer allocator.free(request_body);

    var client = jev.Client.init(allocator, init.io, .{
        .adapter = adapter,
        .max_request_bytes = config.max_request_bytes,
        .max_response_bytes = config.max_response_bytes,
        .connect_timeout_ms = config.connect_timeout_ms,
        .request_timeout_ms = config.request_timeout_ms,
        .retry = .{ .max_attempts = config.max_attempts },
    });
    client.circuit = persisted_circuit;
    var result = client.decide(request_body, secret.bytes) catch |err| {
        try circuit_store.save(allocator, client.circuit);
        return err;
    };
    defer result.deinit();
    persisted_circuit = client.circuit;
    try circuit_store.save(allocator, persisted_circuit);

    // Keep stdout machine-readable and byte-for-byte provider-originated.
    try stdout.writeAll(result.body);
    if (result.body.len == 0 or result.body[result.body.len - 1] != '\n') try stdout.writeByte('\n');
    try stdout.flush();

    if (!result.isSuccess()) {
        try stderr.print("jev-decide: provider returned HTTP {d}\n", .{result.status});
        try stderr.flush();
        std.process.exit(httpExitCode(result.status));
    }
    if (result.resolved_model) |resolved| {
        try stderr.print("jev-decide: resolved model {s}\n", .{resolved});
        try stderr.flush();
    }
}

fn printHelp(writer: *std.Io.Writer) !void {
    try writer.writeAll(
        \\Usage: jev-decide [--adapter alpha-decisions|systemone-v1] [--model MODEL]
        \\       jev-decide --store-key
        \\
        \\Read one Jev decision request as JSON from stdin and write the provider JSON
        \\response to stdout. Diagnostics go to stderr. Credentials are loaded from
        \\OPENROUTER_API_KEY, then the native credential store on macOS or Windows
        \\using non-secret config at ~/.config/jev-openrouter/config.json. Linux uses
        \\the session-only environment variable. API keys are never accepted as arguments.
        \\
        \\Options:
        \\  --adapter NAME  Select one API contract explicitly; no automatic failover.
        \\  --model MODEL   Supply/override the request model.
        \\  --health        Check configuration and credential availability; no API call.
        \\  --store-key     Read one API key from stdin and save it in the native store.
        \\  -h, --help      Show this help.
        \\
    );
}

fn loadConfig(
    allocator: std.mem.Allocator,
    io: std.Io,
    environ: *const std.process.Environ.Map,
) !Config {
    var config = try Config.defaults(allocator);
    errdefer config.deinit();

    const home = homeDirectory(environ) orelse return config;
    const path = try std.fs.path.join(allocator, &.{ home, ".config/jev-openrouter/config.json" });
    defer allocator.free(path);

    const file = std.Io.Dir.openFileAbsolute(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => return config,
        else => return err,
    };
    defer file.close(io);
    var read_buffer: [4096]u8 = undefined;
    var file_reader = file.reader(io, &read_buffer);
    const bytes = file_reader.interface.allocRemaining(allocator, .limited(config_limit)) catch |err| switch (err) {
        error.StreamTooLong => return error.ConfigTooLarge,
        else => return err,
    };
    defer allocator.free(bytes);

    try applyConfigJson(&config, bytes);
    config.loaded = true;
    return config;
}

fn applyConfigJson(config: *Config, bytes: []const u8) !void {
    var parsed = try std.json.parseFromSlice(std.json.Value, config.allocator, bytes, .{});
    defer parsed.deinit();
    const root = switch (parsed.value) {
        .object => |object| object,
        else => return error.ConfigMustBeObject,
    };

    if (root.get("endpoint")) |endpoint_value| {
        const endpoint = switch (endpoint_value) {
            .string => |text| text,
            else => return error.InvalidConfigEndpoint,
        };
        config.adapter = adapterFromEndpoint(endpoint) orelse return error.InvalidConfigEndpoint;
    }
    if (root.get("adapter")) |adapter_value| {
        const adapter_text = switch (adapter_value) {
            .string => |text| text,
            else => return error.InvalidConfigAdapter,
        };
        config.adapter = decision.Adapter.parse(adapter_text) catch return error.InvalidConfigAdapter;
    }
    if (root.get("model")) |model_value| {
        const model = switch (model_value) {
            .string => |text| text,
            else => return error.InvalidConfigModel,
        };
        if (model.len == 0) return error.InvalidConfigModel;
        const replacement = try config.allocator.dupe(u8, model);
        if (config.model) |old| config.allocator.free(old);
        config.model = replacement;
    }
    if (root.get("keychain")) |keychain_value| {
        const keychain = switch (keychain_value) {
            .object => |object| object,
            else => return error.InvalidKeychainConfig,
        };
        if (keychain.get("service")) |service_value| {
            const service = switch (service_value) {
                .string => |text| text,
                else => return error.InvalidKeychainConfig,
            };
            if (service.len == 0) return error.InvalidKeychainConfig;
            const replacement = try config.allocator.dupe(u8, service);
            config.allocator.free(config.keychain_service);
            config.keychain_service = replacement;
        }
        if (keychain.get("account")) |account_value| {
            const account = switch (account_value) {
                .string => |text| text,
                else => return error.InvalidKeychainConfig,
            };
            if (account.len == 0) return error.InvalidKeychainConfig;
            const replacement = try config.allocator.dupe(u8, account);
            if (config.keychain_account) |old| config.allocator.free(old);
            config.keychain_account = replacement;
        }
    }
    if (root.get("limits")) |limits_value| {
        const limits = switch (limits_value) {
            .object => |object| object,
            else => return error.InvalidLimitsConfig,
        };
        if (limits.get("requestBytes")) |value| config.max_request_bytes = try positiveUsize(value);
        if (limits.get("responseBytes")) |value| config.max_response_bytes = try positiveUsize(value);
        if (limits.get("maxAttempts")) |value| {
            const attempts = try positiveUsize(value);
            if (attempts > 10) return error.InvalidLimitsConfig;
            config.max_attempts = @intCast(attempts);
        }
    }
    if (root.get("timeouts")) |timeouts_value| {
        const timeouts = switch (timeouts_value) {
            .object => |object| object,
            else => return error.InvalidTimeoutConfig,
        };
        if (timeouts.get("connectSeconds")) |value| {
            config.connect_timeout_ms = try timeoutSecondsToMilliseconds(value, max_connect_timeout_seconds);
        }
        if (timeouts.get("requestSeconds")) |value| {
            config.request_timeout_ms = try timeoutSecondsToMilliseconds(value, max_request_timeout_seconds);
        }
    }
}

fn positiveUsize(value: std.json.Value) !usize {
    const integer = switch (value) {
        .integer => |number| number,
        else => return error.InvalidLimitsConfig,
    };
    if (integer <= 0) return error.InvalidLimitsConfig;
    return std.math.cast(usize, integer) orelse error.InvalidLimitsConfig;
}

fn timeoutSecondsToMilliseconds(value: std.json.Value, maximum_seconds: usize) !u64 {
    const seconds = positiveUsize(value) catch return error.InvalidTimeoutConfig;
    if (seconds > maximum_seconds) return error.InvalidTimeoutConfig;
    const seconds_u64 = std.math.cast(u64, seconds) orelse return error.InvalidTimeoutConfig;
    return std.math.mul(u64, seconds_u64, 1000) catch error.InvalidTimeoutConfig;
}

fn adapterFromEndpoint(endpoint: []const u8) ?decision.Adapter {
    if (std.mem.eql(u8, endpoint, decision.Adapter.alpha_decisions.endpoint())) return .alpha_decisions;
    if (std.mem.eql(u8, endpoint, decision.Adapter.systemone_v1.endpoint())) return .systemone_v1;
    return null;
}

fn homeDirectory(environ: *const std.process.Environ.Map) ?[]const u8 {
    return environ.get("HOME") orelse environ.get("USERPROFILE");
}

fn openCircuitStore(
    allocator: std.mem.Allocator,
    io: std.Io,
    environ: *const std.process.Environ.Map,
    adapter: decision.Adapter,
) !CircuitStore {
    const home = homeDirectory(environ) orelse return error.CircuitStateUnavailable;
    const directory_path = try std.fs.path.join(allocator, &.{ home, ".config", "jev-openrouter" });
    defer allocator.free(directory_path);

    var directory = try std.Io.Dir.cwd().createDirPathOpen(io, directory_path, .{
        .permissions = secureDirectoryPermissions(),
    });
    if (builtin.os.tag != .windows and std.Io.File.Permissions.has_executable_bit) {
        directory.setPermissions(io, secureDirectoryPermissions()) catch |err| {
            directory.close(io);
            return err;
        };
    }
    const filename = switch (adapter) {
        .alpha_decisions => "circuit-alpha-decisions.json",
        .systemone_v1 => "circuit-systemone-v1.json",
    };
    return CircuitStore.openOwned(io, directory, filename);
}

fn openCircuitFile(dir: std.Io.Dir, io: std.Io, name: []const u8) !std.Io.File {
    var file = try dir.createFile(io, name, .{
        .read = true,
        .truncate = false,
        .lock = .exclusive,
        .permissions = secureFilePermissions(),
    });
    errdefer file.close(io);
    if (builtin.os.tag != .windows and std.Io.File.Permissions.has_executable_bit) {
        try file.setPermissions(io, secureFilePermissions());
    }
    return file;
}

fn parseCircuitState(allocator: std.mem.Allocator, bytes: []const u8) !jev.CircuitBreaker {
    var parsed = std.json.parseFromSlice(CircuitStateWire, allocator, bytes, .{}) catch
        return error.InvalidCircuitState;
    defer parsed.deinit();
    const wire = parsed.value;
    if (wire.version != 1 or
        wire.consecutive_transient_failures > jev.CircuitBreaker.failure_threshold or
        wire.open_until_epoch_ms < 0 or
        (wire.consecutive_transient_failures < jev.CircuitBreaker.failure_threshold and wire.open_until_epoch_ms != 0) or
        (wire.consecutive_transient_failures == jev.CircuitBreaker.failure_threshold and wire.open_until_epoch_ms == 0))
    {
        return error.InvalidCircuitState;
    }
    return .{
        .consecutive_transient_failures = wire.consecutive_transient_failures,
        .open_until_ms = wire.open_until_epoch_ms,
    };
}

fn secureFilePermissions() std.Io.File.Permissions {
    return switch (builtin.os.tag) {
        .linux, .macos, .freebsd, .netbsd, .openbsd, .dragonfly, .illumos => std.Io.File.Permissions.fromMode(0o600),
        else => .default_file,
    };
}

fn secureDirectoryPermissions() std.Io.File.Permissions {
    return switch (builtin.os.tag) {
        .linux, .macos, .freebsd, .netbsd, .openbsd, .dragonfly, .illumos => std.Io.File.Permissions.fromMode(0o700),
        else => .default_dir,
    };
}

fn prepareRequest(
    allocator: std.mem.Allocator,
    input: []const u8,
    default_model: ?[]const u8,
    max_bytes: usize,
) ![]u8 {
    if (input.len == 0) return error.EmptyBody;
    if (input.len > max_bytes) return error.BodyTooLarge;
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, input, .{
        .duplicate_field_behavior = .@"error",
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidDecisionRequest,
    };
    defer parsed.deinit();
    switch (parsed.value) {
        .object => |*object| {
            if (object.get("model") == null) {
                const model = default_model orelse return error.MissingModel;
                try object.put(parsed.arena.allocator(), "model", .{ .string = model });
            }
        },
        else => return error.RequestMustBeObject,
    }
    const normalized = try std.json.Stringify.valueAlloc(allocator, parsed.value, .{});
    errdefer allocator.free(normalized);
    if (normalized.len > max_bytes) return error.BodyTooLarge;
    var validated = decision.validateRequest(allocator, normalized, max_bytes) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidDecisionRequest,
    };
    validated.deinit();
    return normalized;
}

fn loadSecret(
    allocator: std.mem.Allocator,
    environ: *const std.process.Environ.Map,
    service: []const u8,
    account: ?[]const u8,
) !Secret {
    if (environ.get("OPENROUTER_API_KEY")) |key| {
        jev.validateApiKey(key) catch |err| return switch (err) {
            error.MissingApiKey => error.EmptyApiKey,
            else => err,
        };
        return .{
            .allocator = allocator,
            .bytes = try allocator.dupe(u8, key),
            .source = .environment,
        };
    }
    const key = switch (builtin.os.tag) {
        .macos => try loadMacOsKeychain(allocator, service, account),
        .windows => try loadWindowsCredential(allocator, service, account orelse "default"),
        else => return error.CredentialUnavailable,
    };
    errdefer {
        std.crypto.secureZero(u8, key);
        allocator.free(key);
    }
    try jev.validateApiKey(key);
    return .{
        .allocator = allocator,
        .bytes = key,
        .source = if (builtin.os.tag == .windows) .credential_manager else .keychain,
    };
}

fn storeCredential(
    allocator: std.mem.Allocator,
    service: []const u8,
    account: []const u8,
    key: []const u8,
) !void {
    return switch (builtin.os.tag) {
        .macos => storeMacOsKeychain(service, account, key),
        .windows => storeWindowsCredential(allocator, service, account, key),
        else => error.PersistentCredentialStoreUnsupported,
    };
}

fn loadMacOsKeychain(
    allocator: std.mem.Allocator,
    service: []const u8,
    account: ?[]const u8,
) ![]u8 {
    if (builtin.os.tag != .macos) return error.CredentialUnavailable;
    if (service.len > std.math.maxInt(u32)) return error.InvalidKeychainConfig;
    if (account) |name| if (name.len > std.math.maxInt(u32)) return error.InvalidKeychainConfig;

    var library = std.DynLib.open("/System/Library/Frameworks/Security.framework/Security") catch
        return error.KeychainUnavailable;
    defer library.close();

    const FindPassword = *const fn (
        ?*anyopaque,
        u32,
        [*]const u8,
        u32,
        ?[*]const u8,
        *u32,
        *?*anyopaque,
        ?*?*anyopaque,
    ) callconv(.c) i32;
    const FreeContent = *const fn (?*anyopaque, ?*anyopaque) callconv(.c) i32;
    const find_password = library.lookup(FindPassword, "SecKeychainFindGenericPassword") orelse
        return error.KeychainUnavailable;
    const free_content = library.lookup(FreeContent, "SecKeychainItemFreeContent") orelse
        return error.KeychainUnavailable;

    var password_len: u32 = 0;
    var password_data: ?*anyopaque = null;
    const account_len: u32 = if (account) |name| @intCast(name.len) else 0;
    const account_ptr: ?[*]const u8 = if (account) |name| name.ptr else null;
    const status = find_password(
        null,
        @intCast(service.len),
        service.ptr,
        account_len,
        account_ptr,
        &password_len,
        &password_data,
        null,
    );
    if (status != 0 or password_data == null or password_len == 0) return error.CredentialUnavailable;
    defer _ = free_content(null, password_data);

    const source: [*]const u8 = @ptrCast(password_data.?);
    return allocator.dupe(u8, source[0..password_len]);
}

fn storeMacOsKeychain(service: []const u8, account: []const u8, key: []const u8) !void {
    if (builtin.os.tag != .macos) return error.PersistentCredentialStoreUnsupported;
    if (service.len > std.math.maxInt(u32) or account.len > std.math.maxInt(u32) or key.len > std.math.maxInt(u32))
        return error.InvalidKeychainConfig;

    var library = std.DynLib.open("/System/Library/Frameworks/Security.framework/Security") catch
        return error.KeychainUnavailable;
    defer library.close();

    const FindPassword = *const fn (
        ?*anyopaque,
        u32,
        [*]const u8,
        u32,
        ?[*]const u8,
        *u32,
        *?*anyopaque,
        ?*?*anyopaque,
    ) callconv(.c) i32;
    const FreeContent = *const fn (?*anyopaque, ?*anyopaque) callconv(.c) i32;
    const ModifyPassword = *const fn (
        *anyopaque,
        ?*const anyopaque,
        u32,
        ?*const anyopaque,
    ) callconv(.c) i32;
    const AddPassword = *const fn (
        ?*anyopaque,
        u32,
        [*]const u8,
        u32,
        [*]const u8,
        u32,
        [*]const u8,
        ?*?*anyopaque,
    ) callconv(.c) i32;
    const find_password = library.lookup(FindPassword, "SecKeychainFindGenericPassword") orelse
        return error.KeychainUnavailable;
    const free_content = library.lookup(FreeContent, "SecKeychainItemFreeContent") orelse
        return error.KeychainUnavailable;
    const modify_password = library.lookup(ModifyPassword, "SecKeychainItemModifyAttributesAndData") orelse
        return error.KeychainUnavailable;
    const add_password = library.lookup(AddPassword, "SecKeychainAddGenericPassword") orelse
        return error.KeychainUnavailable;

    var old_len: u32 = 0;
    var old_data: ?*anyopaque = null;
    var item: ?*anyopaque = null;
    const find_status = find_password(
        null,
        @intCast(service.len),
        service.ptr,
        @intCast(account.len),
        account.ptr,
        &old_len,
        &old_data,
        &item,
    );
    defer {
        if (old_data != null) _ = free_content(null, old_data);
    }

    const status = if (find_status == 0 and item != null)
        modify_password(item.?, null, @intCast(key.len), key.ptr)
    else if (find_status == -25300) // errSecItemNotFound
        add_password(
            null,
            @intCast(service.len),
            service.ptr,
            @intCast(account.len),
            account.ptr,
            @intCast(key.len),
            key.ptr,
            null,
        )
    else
        find_status;
    if (status != 0) return error.CredentialStoreFailed;
}

const WindowsCredential = extern struct {
    flags: u32,
    credential_type: u32,
    target_name: ?[*:0]u16,
    comment: ?[*:0]u16,
    last_written: std.os.windows.FILETIME,
    credential_blob_size: u32,
    credential_blob: ?[*]u8,
    persist: u32,
    attribute_count: u32,
    attributes: ?*anyopaque,
    target_alias: ?[*:0]u16,
    user_name: ?[*:0]u16,
};

const credential_type_generic: u32 = 1;
const credential_persist_local_machine: u32 = 2;

extern "advapi32" fn CredReadW(
    target_name: [*:0]const u16,
    credential_type: u32,
    flags: u32,
    credential: *?*WindowsCredential,
) callconv(.winapi) std.os.windows.BOOL;

extern "advapi32" fn CredWriteW(
    credential: *const WindowsCredential,
    flags: u32,
) callconv(.winapi) std.os.windows.BOOL;

extern "advapi32" fn CredFree(buffer: *anyopaque) callconv(.winapi) void;

fn windowsCredentialTarget(allocator: std.mem.Allocator, service: []const u8, account: []const u8) ![:0]u16 {
    const target = try std.fmt.allocPrint(allocator, "JevOpenRouter/{s}/{s}", .{ service, account });
    defer allocator.free(target);
    return std.unicode.utf8ToUtf16LeAllocZ(allocator, target);
}

fn loadWindowsCredential(
    allocator: std.mem.Allocator,
    service: []const u8,
    account: []const u8,
) ![]u8 {
    if (builtin.os.tag != .windows) return error.CredentialUnavailable;
    const target = try windowsCredentialTarget(allocator, service, account);
    defer allocator.free(target);

    var credential: ?*WindowsCredential = null;
    if (CredReadW(target.ptr, credential_type_generic, 0, &credential) == .FALSE) {
        return switch (std.os.windows.GetLastError()) {
            .NOT_FOUND => error.CredentialUnavailable,
            else => error.CredentialStoreFailed,
        };
    }
    const stored = credential orelse return error.CredentialStoreFailed;
    defer CredFree(@ptrCast(stored));
    if (stored.credential_blob_size == 0 or stored.credential_blob_size > jev.max_api_key_bytes)
        return error.InvalidApiKey;
    const blob = stored.credential_blob orelse return error.InvalidApiKey;
    return allocator.dupe(u8, blob[0..stored.credential_blob_size]);
}

fn storeWindowsCredential(
    allocator: std.mem.Allocator,
    service: []const u8,
    account: []const u8,
    key: []const u8,
) !void {
    if (builtin.os.tag != .windows) return error.PersistentCredentialStoreUnsupported;
    if (key.len > std.math.maxInt(u32)) return error.ApiKeyTooLong;
    const target = try windowsCredentialTarget(allocator, service, account);
    defer allocator.free(target);
    const user_name = try std.unicode.utf8ToUtf16LeAllocZ(allocator, account);
    defer allocator.free(user_name);

    var credential: WindowsCredential = .{
        .flags = 0,
        .credential_type = credential_type_generic,
        .target_name = @constCast(target.ptr),
        .comment = null,
        .last_written = std.mem.zeroes(std.os.windows.FILETIME),
        .credential_blob_size = @intCast(key.len),
        .credential_blob = @constCast(key.ptr),
        .persist = credential_persist_local_machine,
        .attribute_count = 0,
        .attributes = null,
        .target_alias = null,
        .user_name = @constCast(user_name.ptr),
    };
    if (CredWriteW(&credential, 0) == .FALSE) return error.CredentialStoreFailed;
}

fn exitCode(err: anyerror) u8 {
    return switch (err) {
        error.UnknownArgument,
        error.MissingAdapterValue,
        error.MissingModelValue,
        error.UnknownAdapter,
        error.ConflictingModes,
        error.MissingModel,
        error.BodyTooLarge,
        error.EmptyBody,
        error.RequestMustBeObject,
        error.UnsupportedQuestionType,
        error.InvalidDecisionRequest,
        error.ConfigTooLarge,
        error.ConfigMustBeObject,
        error.InvalidConfigEndpoint,
        error.InvalidConfigAdapter,
        error.InvalidConfigModel,
        error.InvalidKeychainConfig,
        error.InvalidLimitsConfig,
        error.InvalidTimeoutConfig,
        error.InvalidTimeout,
        => exit_codes.usage,
        error.MissingApiKey,
        error.EmptyApiKey,
        error.InvalidApiKey,
        error.ApiKeyTooLong,
        error.CredentialUnavailable,
        error.KeychainUnavailable,
        error.CredentialStoreFailed,
        => exit_codes.authentication,
        error.PersistentCredentialStoreUnsupported,
        error.CircuitStateUnavailable,
        => exit_codes.dependency,
        error.CircuitOpen,
        error.TransportFailureBeforeSend,
        error.TransportTimeoutBeforeSend,
        error.AmbiguousPostSendFailure,
        => exit_codes.transient,
        error.ResponseMustBeObject,
        error.MissingAnswers,
        error.AnswersMustBeObject,
        error.MissingUsage,
        error.UsageMustBeObject,
        error.MissingInputTokens,
        error.MissingOutputTokens,
        error.InvalidTokenCount,
        error.AnswerMustBeObject,
        error.MissingAnswerType,
        error.InvalidAnswerType,
        error.MissingChoice,
        error.InvalidChoice,
        error.MissingNoul,
        error.InvalidNoul,
        error.MissingScore,
        error.InvalidScore,
        error.UnsupportedAnswerType,
        error.InvalidConfidence,
        error.InvalidProbabilities,
        error.InvalidProbability,
        error.InvalidProbabilitySum,
        error.ResponseTooLarge,
        error.DuplicateField,
        error.InvalidProviderResponse,
        error.InvalidEndpoint,
        => exit_codes.protocol,
        else => exit_codes.agent,
    };
}

fn httpExitCode(status: u16) u8 {
    if (status == 401 or status == 402 or status == 403 or status == 407)
        return exit_codes.authentication;
    if (jev.isRetryableStatus(status) or status == 408 or status == 504)
        return exit_codes.transient;
    return exit_codes.protocol;
}

test "config maps only known endpoints and keeps keychain metadata non-secret" {
    var config = try Config.defaults(std.testing.allocator);
    defer config.deinit();
    try applyConfigJson(&config,
        \\{
        \\  "version":1,
        \\  "endpoint":"https://openrouter.ai/api/v1/systemone",
        \\  "model":"~typesafe/jev-latest",
        \\  "keychain":{"service":"openrouter-jev","account":"cli"},
        \\  "limits":{"requestBytes":4096,"responseBytes":8192,"maxAttempts":4},
        \\  "timeouts":{"connectSeconds":7,"requestSeconds":90},
        \\  "unknown_future_field":true
        \\}
    );
    try std.testing.expectEqual(decision.Adapter.systemone_v1, config.adapter);
    try std.testing.expectEqualStrings("~typesafe/jev-latest", config.model.?);
    try std.testing.expectEqualStrings("openrouter-jev", config.keychain_service);
    try std.testing.expectEqualStrings("cli", config.keychain_account.?);
    try std.testing.expectEqual(@as(usize, 4096), config.max_request_bytes);
    try std.testing.expectEqual(@as(u8, 4), config.max_attempts);
    try std.testing.expectEqual(@as(u64, 7000), config.connect_timeout_ms);
    try std.testing.expectEqual(@as(u64, 90_000), config.request_timeout_ms);
}

test "fresh configuration owns the default Jev alias and credential identity" {
    var config = try Config.defaults(std.testing.allocator);
    defer config.deinit();
    try std.testing.expectEqualStrings(decision.default_model, config.model.?);
    try std.testing.expectEqualStrings("jev-openrouter", config.keychain_service);
    try std.testing.expectEqualStrings("default", config.keychain_account.?);
}

fn configDefaultsAllocationCase(allocator: std.mem.Allocator) !void {
    var config = try Config.defaults(allocator);
    defer config.deinit();
}

test "fresh configuration is allocation-failure safe" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, configDefaultsAllocationCase, .{});
}

fn applyConfigAllocationCase(allocator: std.mem.Allocator) !void {
    var config = try Config.defaults(allocator);
    defer config.deinit();
    try applyConfigJson(
        &config,
        "{\"model\":\"~typesafe/jev-stable\",\"keychain\":{\"service\":\"openrouter\",\"account\":\"test\"}}",
    );
}

test "configuration replacement is allocation-failure safe" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, applyConfigAllocationCase, .{});
}

test "unknown endpoint cannot silently select another adapter" {
    var config = try Config.defaults(std.testing.allocator);
    defer config.deinit();
    try std.testing.expectError(error.InvalidConfigEndpoint, applyConfigJson(
        &config,
        "{\"endpoint\":\"https://example.invalid/decisions\"}",
    ));
}

test "default model is injected then full request is validated" {
    const input = "{\"state\":\"hello\",\"questions\":{\"q\":{\"type\":\"noul\",\"instructions\":\"Is it a greeting?\"}}}";
    const normalized = try prepareRequest(std.testing.allocator, input, "~typesafe/jev-latest", decision.default_max_request_bytes);
    defer std.testing.allocator.free(normalized);
    var validated = try decision.validateRequest(std.testing.allocator, normalized, decision.default_max_request_bytes);
    defer validated.deinit();
    try std.testing.expectEqualStrings("~typesafe/jev-latest", validated.model);
}

test "stdin request duplicate fields fail as usage input" {
    const input =
        "{\"state\":\"hello\",\"state\":\"again\",\"questions\":{\"q\":{\"type\":\"noul\",\"instructions\":\"Greeting?\"}}}";
    try std.testing.expectError(
        error.InvalidDecisionRequest,
        prepareRequest(std.testing.allocator, input, decision.default_model, decision.default_max_request_bytes),
    );
    try std.testing.expectEqual(exit_codes.usage, exitCode(error.InvalidDecisionRequest));
}

test "help never suggests accepting a credential argument" {
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try printHelp(&output.writer);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "--api-key") == null);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "native credential store") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "--store-key") != null);
}

test "exit taxonomy separates usage authentication transient and protocol" {
    try std.testing.expectEqual(exit_codes.usage, exitCode(error.UnknownArgument));
    try std.testing.expectEqual(exit_codes.authentication, exitCode(error.CredentialUnavailable));
    try std.testing.expectEqual(exit_codes.transient, exitCode(error.AmbiguousPostSendFailure));
    try std.testing.expectEqual(exit_codes.protocol, exitCode(error.InvalidProviderResponse));
    try std.testing.expectEqual(exit_codes.dependency, exitCode(error.PersistentCredentialStoreUnsupported));
    try std.testing.expectEqual(exit_codes.agent, exitCode(error.OutOfMemory));

    try std.testing.expectEqual(exit_codes.authentication, httpExitCode(401));
    try std.testing.expectEqual(exit_codes.transient, httpExitCode(429));
    try std.testing.expectEqual(exit_codes.transient, httpExitCode(504));
    try std.testing.expectEqual(exit_codes.protocol, httpExitCode(422));
}

test "timeout config is positive and bounded" {
    var config = try Config.defaults(std.testing.allocator);
    defer config.deinit();
    try std.testing.expectError(
        error.InvalidTimeoutConfig,
        applyConfigJson(&config, "{\"timeouts\":{\"connectSeconds\":0}}"),
    );
    try std.testing.expectError(
        error.InvalidTimeoutConfig,
        applyConfigJson(&config, "{\"timeouts\":{\"requestSeconds\":3601}}"),
    );
}

test "circuit breaker state survives store reopen without secret material" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const expected = jev.CircuitBreaker{
        .consecutive_transient_failures = jev.CircuitBreaker.failure_threshold,
        .open_until_ms = 1_900_000_060_000,
    };
    {
        var store = try CircuitStore.openBorrowed(std.testing.io, tmp.dir, "circuit.json");
        defer store.deinit();
        try store.save(std.testing.allocator, expected);
    }
    {
        var store = try CircuitStore.openBorrowed(std.testing.io, tmp.dir, "circuit.json");
        defer store.deinit();
        const actual = try store.load(std.testing.allocator);
        try std.testing.expectEqual(expected.consecutive_transient_failures, actual.consecutive_transient_failures);
        try std.testing.expectEqual(expected.open_until_ms, actual.open_until_ms);
    }

    const bytes = try tmp.dir.readFileAlloc(std.testing.io, "circuit.json", std.testing.allocator, .limited(circuit_state_limit));
    defer std.testing.allocator.free(bytes);
    try std.testing.expect(std.mem.indexOf(u8, bytes, "sk-or-") == null);
    try std.testing.expect(std.mem.indexOf(u8, bytes, "Bearer") == null);
}

test "invalid persisted circuit state is rejected" {
    try std.testing.expectError(
        error.InvalidCircuitState,
        parseCircuitState(
            std.testing.allocator,
            "{\"version\":1,\"consecutive_transient_failures\":3,\"open_until_epoch_ms\":0}",
        ),
    );
}

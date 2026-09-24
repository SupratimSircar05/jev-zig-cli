const std = @import("std");
const builtin = @import("builtin");

pub const key_length = 32;
pub const default_pbkdf2_rounds: u32 = 600_000;
pub const default_service = "jev-zig-cli.audit-master-key.v1";
pub const default_account = "default";

const stored_key_prefix = "jev-audit-key-v1:";
const stored_key_length = stored_key_prefix.len + key_length * 2;

/// An owned audit master key. Call `deinit` as soon as the journal no longer
/// needs it. Zig and the operating system may make unavoidable transient
/// copies while invoking cryptographic APIs; this type wipes its owned copy.
pub const MasterKey = struct {
    bytes: [key_length]u8,

    pub fn init(bytes: [key_length]u8) MasterKey {
        return .{ .bytes = bytes };
    }

    pub fn random(io: std.Io) !MasterKey {
        var bytes: [key_length]u8 = undefined;
        errdefer std.crypto.secureZero(u8, &bytes);
        try io.randomSecure(&bytes);
        return .{ .bytes = bytes };
    }

    pub fn value(self: *const MasterKey) [key_length]u8 {
        return self.bytes;
    }

    pub fn deinit(self: *MasterKey) void {
        std.crypto.secureZero(u8, &self.bytes);
    }
};

/// Interactive fallback hook. The callback must return an allocator-owned
/// mutable slice. `load` wipes and frees it immediately after key derivation.
pub const Prompt = struct {
    context: ?*anyopaque = null,
    read_fn: *const fn (?*anyopaque, std.mem.Allocator, std.Io, []const u8) anyerror![]u8,

    pub fn read(self: Prompt, allocator: std.mem.Allocator, io: std.Io, message: []const u8) ![]u8 {
        return self.read_fn(self.context, allocator, io, message);
    }

    /// Hidden `/dev/tty` prompt for POSIX terminals. Windows uses the native
    /// Credential Manager backend and therefore does not need this fallback.
    pub fn tty() Prompt {
        return .{ .read_fn = ttyPrompt };
    }
};

pub const LoadOptions = struct {
    /// Kept deliberately separate from the OpenRouter credential: this item
    /// encrypts only the local audit journal.
    service: []const u8 = default_service,
    account: []const u8 = default_account,
    pbkdf2_rounds: u32 = default_pbkdf2_rounds,
    /// Source environment used only to copy the minimal non-secret variables
    /// needed by the native credential service. It is never inherited whole.
    environ_map: ?*const std.process.Environ.Map = null,
    /// Linux uses this when Secret Service (`secret-tool`) is absent or has no
    /// matching item. It may also be supplied on macOS for an explicit recovery
    /// path when Keychain has no matching item.
    prompt: ?Prompt = null,
};

/// Loads a secret without ever placing secret bytes in argv, logs, source, or
/// environment variables. macOS reads Keychain via `/usr/bin/security`;
/// Linux reads Secret Service via `secret-tool` and then uses the configured
/// interactive fallback. Windows uses the native Credential Manager API.
pub fn load(allocator: std.mem.Allocator, io: std.Io, options: LoadOptions) !MasterKey {
    try validateOptions(options);
    return switch (builtin.os.tag) {
        .macos => loadMacOS(allocator, io, options) catch |err| switch (err) {
            error.OutOfMemory, error.Canceled, error.Timeout, error.InvalidStoredSecret => return err,
            else => fallbackPrompt(allocator, io, options, err),
        },
        .linux => loadLinux(allocator, io, options) catch |err| switch (err) {
            error.OutOfMemory, error.Canceled, error.Timeout, error.InvalidStoredSecret => return err,
            else => fallbackPrompt(allocator, io, options, err),
        },
        .windows => loadWindows(allocator, options),
        else => fallbackPrompt(allocator, io, options, error.UnsupportedSecretStore),
    };
}

/// Saves an audit master key in the platform credential store. The key is
/// supplied through a child process's stdin on macOS/Linux and through the
/// native Credential Manager API on Windows; it is never placed in argv or an
/// environment variable.
pub fn save(
    allocator: std.mem.Allocator,
    io: std.Io,
    options: LoadOptions,
    master_key: *const MasterKey,
) !void {
    try validateOptions(options);
    return switch (builtin.os.tag) {
        .macos => saveMacOS(allocator, io, options, master_key),
        .linux => saveLinux(allocator, io, options, master_key),
        .windows => saveWindows(allocator, options, master_key),
        else => error.UnsupportedSecretStore,
    };
}

/// Loads the dedicated audit key or generates, persists, and re-reads a
/// cryptographically random one. Re-reading prevents the caller from using a
/// key that a provider failed to persist. If the native store is unavailable,
/// POSIX callers may opt into the deterministic hidden-passphrase fallback.
pub fn loadOrCreate(
    allocator: std.mem.Allocator,
    io: std.Io,
    options: LoadOptions,
) !MasterKey {
    try validateOptions(options);

    const existing = loadNative(allocator, io, options);
    if (existing) |key| return key else |load_error| switch (load_error) {
        error.OutOfMemory, error.Canceled, error.Timeout, error.InvalidStoredSecret => return load_error,
        error.SecretNotFound => {},
        else => return fallbackPrompt(allocator, io, options, load_error),
    }

    var generated = try MasterKey.random(io);
    defer generated.deinit();
    save(allocator, io, options, &generated) catch |save_error| {
        return fallbackPrompt(allocator, io, options, save_error);
    };

    // A provider may resolve a concurrent create/update to a different value;
    // the credential store is authoritative, so use only the value read back.
    return loadNative(allocator, io, options) catch |reload_error| {
        return fallbackPrompt(allocator, io, options, reload_error);
    };
}

/// Derives a fixed-size master key from secret material. The public context is
/// folded into a domain-separated salt so keys are not reused across services.
pub fn deriveMasterKey(secret: []const u8, context: []const u8, rounds: u32) !MasterKey {
    if (secret.len == 0) return error.EmptySecret;
    if (rounds == 0) return error.WeakParameters;

    var salt_hash = std.crypto.hash.sha2.Sha256.init(.{});
    salt_hash.update("jev-zig-cli/audit-master-key/v1\x00");
    salt_hash.update(context);
    var salt: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    salt_hash.final(&salt);

    var key: [key_length]u8 = undefined;
    errdefer std.crypto.secureZero(u8, &key);
    try std.crypto.pwhash.pbkdf2(
        &key,
        secret,
        &salt,
        rounds,
        std.crypto.auth.hmac.sha2.HmacSha256,
    );
    return .{ .bytes = key };
}

fn loadMacOS(allocator: std.mem.Allocator, io: std.Io, options: LoadOptions) !MasterKey {
    return loadCommandSecret(allocator, io, options, &.{
        "/usr/bin/security",
        "find-generic-password",
        "-s",
        options.service,
        "-a",
        options.account,
        "-w",
    });
}

fn saveMacOS(
    allocator: std.mem.Allocator,
    io: std.Io,
    options: LoadOptions,
    master_key: *const MasterKey,
) !void {
    var encoded = encodeStoredKey(master_key);
    defer std.crypto.secureZero(u8, &encoded);

    // `security add-generic-password -w` prompts on /dev/tty, not stdin. Its
    // interactive mode accepts the whole command on stdin, keeping the secret
    // out of the process list. Credential names are restricted to inert token
    // characters by validateOptions, so they cannot inject another command.
    const fixed_len = "add-generic-password -U -a  -s  -w \n".len;
    const names_len = std.math.add(usize, options.account.len, options.service.len) catch return error.InputTooLong;
    const command_len = std.math.add(usize, fixed_len + stored_key_length, names_len) catch return error.InputTooLong;
    var command: std.ArrayList(u8) = .empty;
    defer {
        std.crypto.secureZero(u8, command.items);
        command.deinit(allocator);
    }
    try command.ensureTotalCapacityPrecise(allocator, command_len);
    try command.appendSlice(allocator, "add-generic-password -U -a ");
    try command.appendSlice(allocator, options.account);
    try command.appendSlice(allocator, " -s ");
    try command.appendSlice(allocator, options.service);
    try command.appendSlice(allocator, " -w ");
    try command.appendSlice(allocator, &encoded);
    try command.append(allocator, '\n');
    std.debug.assert(command.items.len == command_len);
    return runCommandInput(allocator, io, options.environ_map, &.{ "/usr/bin/security", "-i" }, command.items);
}

fn loadLinux(allocator: std.mem.Allocator, io: std.Io, options: LoadOptions) !MasterKey {
    return loadCommandSecret(allocator, io, options, &.{
        "/usr/bin/secret-tool",
        "lookup",
        "service",
        options.service,
        "account",
        options.account,
    });
}

fn saveLinux(allocator: std.mem.Allocator, io: std.Io, options: LoadOptions, master_key: *const MasterKey) !void {
    var encoded = encodeStoredKey(master_key);
    defer std.crypto.secureZero(u8, &encoded);
    return runSecretInputCommand(allocator, io, options.environ_map, &.{
        "/usr/bin/secret-tool",
        "store",
        "--label=Jev audit master key",
        "service",
        options.service,
        "account",
        options.account,
    }, &encoded);
}

fn loadNative(allocator: std.mem.Allocator, io: std.Io, options: LoadOptions) anyerror!MasterKey {
    return switch (builtin.os.tag) {
        .macos => loadMacOS(allocator, io, options),
        .linux => loadLinux(allocator, io, options),
        .windows => loadWindows(allocator, options),
        else => error.UnsupportedSecretStore,
    };
}

fn loadCommandSecret(
    allocator: std.mem.Allocator,
    io: std.Io,
    options: LoadOptions,
    argv: []const []const u8,
) !MasterKey {
    var helper_environment = try credentialHelperEnvironment(allocator, options.environ_map);
    defer helper_environment.deinit();
    const result = try std.process.run(allocator, io, .{
        .argv = argv,
        .environ_map = &helper_environment,
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(16 * 1024),
        .timeout = .{ .duration = .{
            .raw = .fromSeconds(15),
            .clock = .awake,
        } },
    });
    defer {
        std.crypto.secureZero(u8, result.stdout);
        allocator.free(result.stdout);
        std.crypto.secureZero(u8, result.stderr);
        allocator.free(result.stderr);
    }

    switch (result.term) {
        .exited => |status| if (status != 0) return error.SecretNotFound,
        else => return error.SecretProviderFailed,
    }

    const secret = std.mem.trim(u8, result.stdout, " \t\r\n");
    if (secret.len == 0) return error.SecretNotFound;
    const context = try std.fmt.allocPrint(allocator, "{s}\x00{s}", .{ options.service, options.account });
    defer allocator.free(context);
    return keyFromStoredSecret(secret, context, options.pbkdf2_rounds);
}

fn runSecretInputCommand(
    allocator: std.mem.Allocator,
    io: std.Io,
    source_environment: ?*const std.process.Environ.Map,
    argv: []const []const u8,
    secret: []const u8,
) !void {
    var line: [stored_key_length + 1]u8 = undefined;
    defer std.crypto.secureZero(u8, &line);
    if (secret.len != stored_key_length) return error.InvalidStoredSecret;
    @memcpy(line[0..secret.len], secret);
    line[secret.len] = '\n';
    return runCommandInput(allocator, io, source_environment, argv, &line);
}

fn runCommandInput(
    allocator: std.mem.Allocator,
    io: std.Io,
    source_environment: ?*const std.process.Environ.Map,
    argv: []const []const u8,
    input: []const u8,
) !void {
    var helper_environment = try credentialHelperEnvironment(allocator, source_environment);
    defer helper_environment.deinit();
    var child = try std.process.spawn(io, .{
        .argv = argv,
        .environ_map = &helper_environment,
        .stdin = .pipe,
        .stdout = .ignore,
        .stderr = .ignore,
        .create_no_window = true,
    });
    var child_reaped = false;
    defer if (!child_reaped) child.kill(io);

    const stdin_file = child.stdin.?;
    child.stdin = null;
    var stdin_closed = false;
    defer if (!stdin_closed) stdin_file.close(io);
    try stdin_file.writeStreamingAll(io, input);
    stdin_file.close(io);
    stdin_closed = true;

    const timeout: std.Io.Timeout = .{ .deadline = .fromNow(io, .{
        .raw = .fromSeconds(15),
        .clock = .awake,
    }) };
    const term = try waitChild(&child, io, timeout);
    child_reaped = true;
    switch (term) {
        .exited => |status| if (status != 0) return error.SecretProviderFailed,
        else => return error.SecretProviderFailed,
    }
}

fn credentialHelperEnvironment(
    allocator: std.mem.Allocator,
    source: ?*const std.process.Environ.Map,
) !std.process.Environ.Map {
    var result = std.process.Environ.Map.init(allocator);
    errdefer result.deinit();
    const input = source orelse return result;
    const allowed = [_][]const u8{
        "HOME",
        "USER",
        "LOGNAME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "DBUS_SESSION_BUS_ADDRESS",
        "XDG_RUNTIME_DIR",
        "DISPLAY",
        "WAYLAND_DISPLAY",
    };
    for (allowed) |name| if (input.get(name)) |value| try result.put(name, value);
    return result;
}

fn waitChild(child: *std.process.Child, io: std.Io, timeout: std.Io.Timeout) !std.process.Child.Term {
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
            return error.Timeout;
        },
    }
}

fn fallbackPrompt(
    allocator: std.mem.Allocator,
    io: std.Io,
    options: LoadOptions,
    original_error: anyerror,
) !MasterKey {
    const prompt = options.prompt orelse return original_error;
    const secret = try prompt.read(allocator, io, "Jev audit passphrase: ");
    defer {
        std.crypto.secureZero(u8, secret);
        allocator.free(secret);
    }
    const context = try std.fmt.allocPrint(allocator, "{s}\x00{s}", .{ options.service, options.account });
    defer allocator.free(context);
    return deriveMasterKey(std.mem.trim(u8, secret, "\r\n"), context, options.pbkdf2_rounds);
}

fn validateOptions(options: LoadOptions) !void {
    if (options.service.len == 0 or options.account.len == 0) return error.InvalidCredentialName;
    if (options.service.len > 1024 or options.account.len > 1024) return error.InvalidCredentialName;
    if (options.pbkdf2_rounds == 0) return error.WeakParameters;
    for (options.service) |byte| if (!isCredentialNameByte(byte)) return error.InvalidCredentialName;
    for (options.account) |byte| if (!isCredentialNameByte(byte)) return error.InvalidCredentialName;
}

fn isCredentialNameByte(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '-' or byte == '_' or byte == '.' or byte == '@';
}

fn encodeStoredKey(master_key: *const MasterKey) [stored_key_length]u8 {
    var result: [stored_key_length]u8 = undefined;
    @memcpy(result[0..stored_key_prefix.len], stored_key_prefix);
    var hex = std.fmt.bytesToHex(master_key.bytes, .lower);
    defer std.crypto.secureZero(u8, &hex);
    @memcpy(result[stored_key_prefix.len..], &hex);
    return result;
}

fn keyFromStoredSecret(secret: []const u8, context: []const u8, rounds: u32) !MasterKey {
    if (!std.mem.startsWith(u8, secret, stored_key_prefix)) {
        return deriveMasterKey(secret, context, rounds);
    }
    if (secret.len != stored_key_length) return error.InvalidStoredSecret;

    var key: [key_length]u8 = undefined;
    errdefer std.crypto.secureZero(u8, &key);
    _ = std.fmt.hexToBytes(&key, secret[stored_key_prefix.len..]) catch return error.InvalidStoredSecret;
    return .{ .bytes = key };
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

extern "kernel32" fn GetConsoleMode(
    handle: std.os.windows.HANDLE,
    mode: *u32,
) callconv(.winapi) std.os.windows.BOOL;

extern "kernel32" fn SetConsoleMode(
    handle: std.os.windows.HANDLE,
    mode: u32,
) callconv(.winapi) std.os.windows.BOOL;

fn windowsTarget(allocator: std.mem.Allocator, options: LoadOptions) ![:0]u16 {
    const target = try std.fmt.allocPrint(allocator, "JevAudit/{s}/{s}", .{ options.service, options.account });
    defer allocator.free(target);
    return std.unicode.utf8ToUtf16LeAllocZ(allocator, target);
}

fn loadWindows(allocator: std.mem.Allocator, options: LoadOptions) !MasterKey {
    const target = try windowsTarget(allocator, options);
    defer allocator.free(target);

    var credential: ?*WindowsCredential = null;
    if (CredReadW(target.ptr, credential_type_generic, 0, &credential) == .FALSE) {
        return switch (std.os.windows.GetLastError()) {
            .NOT_FOUND => error.SecretNotFound,
            else => error.SecretProviderFailed,
        };
    }
    const stored = credential orelse return error.SecretProviderFailed;
    defer CredFree(@ptrCast(stored));
    if (stored.credential_blob_size != key_length) return error.InvalidStoredSecret;
    const blob = stored.credential_blob orelse return error.InvalidStoredSecret;

    var key: [key_length]u8 = undefined;
    @memcpy(&key, blob[0..key_length]);
    return .{ .bytes = key };
}

fn saveWindows(allocator: std.mem.Allocator, options: LoadOptions, master_key: *const MasterKey) !void {
    const target = try windowsTarget(allocator, options);
    defer allocator.free(target);
    const user_name = try std.unicode.utf8ToUtf16LeAllocZ(allocator, options.account);
    defer allocator.free(user_name);

    var key = master_key.value();
    defer std.crypto.secureZero(u8, &key);
    var credential: WindowsCredential = .{
        .flags = 0,
        .credential_type = credential_type_generic,
        .target_name = @constCast(target.ptr),
        .comment = null,
        .last_written = std.mem.zeroes(std.os.windows.FILETIME),
        .credential_blob_size = key_length,
        .credential_blob = key[0..].ptr,
        .persist = credential_persist_local_machine,
        .attribute_count = 0,
        .attributes = null,
        .target_alias = null,
        .user_name = @constCast(user_name.ptr),
    };
    if (CredWriteW(&credential, 0) == .FALSE) return error.SecretProviderFailed;
}

fn ttyPrompt(_: ?*anyopaque, allocator: std.mem.Allocator, io: std.Io, message: []const u8) ![]u8 {
    if (builtin.os.tag == .windows) return windowsConsolePrompt(allocator, io, message);
    switch (builtin.os.tag) {
        .linux, .macos, .freebsd, .netbsd, .openbsd, .dragonfly => {},
        else => return error.UnsupportedSecretStore,
    }

    var tty = try std.Io.Dir.openFileAbsolute(io, "/dev/tty", .{ .mode = .read_write });
    defer tty.close(io);

    var original = try std.posix.tcgetattr(tty.handle);
    var hidden = original;
    hidden.lflag.ECHO = false;
    try std.posix.tcsetattr(tty.handle, .NOW, hidden);
    var restored = false;
    defer if (!restored) std.posix.tcsetattr(tty.handle, .NOW, original) catch {};

    try tty.writeStreamingAll(io, message);
    var passphrase: std.ArrayList(u8) = .empty;
    errdefer {
        std.crypto.secureZero(u8, passphrase.items);
        passphrase.deinit(allocator);
    }

    var byte: [1]u8 = undefined;
    while (passphrase.items.len < 4096) {
        const read = tty.readStreaming(io, &.{&byte}) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (read == 0) continue;
        if (byte[0] == '\n' or byte[0] == '\r') break;
        try passphrase.append(allocator, byte[0]);
    }
    if (passphrase.items.len == 4096) return error.SecretTooLong;

    try std.posix.tcsetattr(tty.handle, .NOW, original);
    restored = true;
    original = undefined;
    try tty.writeStreamingAll(io, "\n");
    if (passphrase.items.len == 0) return error.EmptySecret;
    return passphrase.toOwnedSlice(allocator);
}

fn windowsConsolePrompt(allocator: std.mem.Allocator, io: std.Io, message: []const u8) ![]u8 {
    if (builtin.os.tag != .windows) return error.UnsupportedSecretStore;
    const input = std.Io.File.stdin();
    const output = std.Io.File.stderr();
    var original_mode: u32 = 0;
    if (GetConsoleMode(input.handle, &original_mode) == .FALSE) return error.UnsupportedSecretStore;
    const enable_echo_input: u32 = 0x0004;
    if (SetConsoleMode(input.handle, original_mode & ~enable_echo_input) == .FALSE)
        return error.SecretProviderFailed;
    var restored = false;
    defer if (!restored) {
        _ = SetConsoleMode(input.handle, original_mode);
    };

    try output.writeStreamingAll(io, message);
    var secret: std.ArrayList(u8) = .empty;
    errdefer {
        std.crypto.secureZero(u8, secret.items);
        secret.deinit(allocator);
    }
    var byte: [1]u8 = undefined;
    while (secret.items.len < 4096) {
        const count = input.readStreaming(io, &.{&byte}) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (count == 0) continue;
        if (byte[0] == '\r' or byte[0] == '\n') break;
        try secret.append(allocator, byte[0]);
    }
    if (secret.items.len == 4096) return error.SecretTooLong;
    if (SetConsoleMode(input.handle, original_mode) == .FALSE) return error.SecretProviderFailed;
    restored = true;
    try output.writeStreamingAll(io, "\n");
    if (secret.items.len == 0) return error.EmptySecret;
    return secret.toOwnedSlice(allocator);
}

test "master-key derivation is deterministic and context separated" {
    var first = try deriveMasterKey("correct horse battery staple", "service-a", 1_000);
    defer first.deinit();
    var same = try deriveMasterKey("correct horse battery staple", "service-a", 1_000);
    defer same.deinit();
    var other = try deriveMasterKey("correct horse battery staple", "service-b", 1_000);
    defer other.deinit();

    try std.testing.expectEqualSlices(u8, &first.bytes, &same.bytes);
    try std.testing.expect(!std.mem.eql(u8, &first.bytes, &other.bytes));
}

test "master key deinit wipes its owned storage" {
    var key = MasterKey.init([_]u8{0xa5} ** key_length);
    key.deinit();
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** key_length), &key.bytes);
}

test "stored random-key envelope round trips and malformed envelopes fail closed" {
    var original = MasterKey.init(std.fmt.bytesToHex("0123456789abcdef", .lower));
    defer original.deinit();
    var encoded = encodeStoredKey(&original);
    defer std.crypto.secureZero(u8, &encoded);

    var decoded = try keyFromStoredSecret(&encoded, "unused-for-random-keys", 1);
    defer decoded.deinit();
    try std.testing.expectEqualSlices(u8, &original.bytes, &decoded.bytes);
    try std.testing.expectError(
        error.InvalidStoredSecret,
        keyFromStoredSecret(encoded[0 .. encoded.len - 1], "context", 1),
    );
}

test "credential names reject control characters" {
    try std.testing.expectError(error.InvalidCredentialName, validateOptions(.{ .service = "bad\nname" }));
    try std.testing.expectError(error.InvalidCredentialName, validateOptions(.{ .account = "" }));
    try std.testing.expectError(error.InvalidCredentialName, validateOptions(.{ .service = "safe;quit" }));
    try std.testing.expectError(error.InvalidCredentialName, validateOptions(.{ .account = "quoted'name" }));
}

test "credential helper environment excludes credentials and PATH" {
    var source = std.process.Environ.Map.init(std.testing.allocator);
    defer source.deinit();
    try source.put("PATH", "/tmp/attacker-first");
    try source.put("OPENROUTER_API_KEY", "must-not-reach-helper");
    try source.put("AWS_SECRET_ACCESS_KEY", "must-not-reach-helper");
    try source.put("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus");
    try source.put("XDG_RUNTIME_DIR", "/run/user/1000");

    var filtered = try credentialHelperEnvironment(std.testing.allocator, &source);
    defer filtered.deinit();
    try std.testing.expect(filtered.get("PATH") == null);
    try std.testing.expect(filtered.get("OPENROUTER_API_KEY") == null);
    try std.testing.expect(filtered.get("AWS_SECRET_ACCESS_KEY") == null);
    try std.testing.expectEqualStrings("unix:path=/run/user/1000/bus", filtered.get("DBUS_SESSION_BUS_ADDRESS").?);
    try std.testing.expectEqualStrings("/run/user/1000", filtered.get("XDG_RUNTIME_DIR").?);
}

test {
    std.testing.refAllDecls(@This());
}

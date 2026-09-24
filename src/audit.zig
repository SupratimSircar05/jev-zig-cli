const std = @import("std");
const builtin = @import("builtin");
const redact = @import("redact.zig");
const secret_store = @import("secret_store.zig");

const Aead = std.crypto.aead.chacha_poly.XChaCha20Poly1305;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const format_version: u16 = 1;
pub const default_max_plaintext_bytes: u32 = 16 * 1024 * 1024;
pub const SessionId = [16]u8;
pub const ChainHash = [Sha256.digest_length]u8;
pub const RecordKind = enum { post_action, pre_action };

const magic = [_]u8{ 'J', 'E', 'V', 'A', 'U', 'D', '1', 0 };
const header_len = 104;
const trailer_len = Aead.tag_length + Sha256.digest_length;
const pre_action_flag: u16 = 1;
const known_flags: u16 = pre_action_flag;
const zero_hash = [_]u8{0} ** Sha256.digest_length;

pub const Options = struct {
    max_plaintext_bytes: u32 = default_max_plaintext_bytes,
    repair_incomplete_tail: bool = true,
};

pub const Receipt = struct {
    sequence: u64,
    kind: RecordKind,
    session_id: SessionId,
    chain_hash: ChainHash,
    frame_offset: u64,
    frame_length: u64,
    durable: bool = true,
};

pub const VerifyReport = struct {
    record_count: u64,
    valid_bytes: u64,
    truncated_bytes: u64,
    tail_hash: ChainHash,
};

pub const Record = struct {
    sequence: u64,
    kind: RecordKind,
    timestamp_ns: i64,
    session_id: SessionId,
    action: []u8,
    payload: []u8,
    chain_hash: ChainHash,
};

pub const Records = struct {
    allocator: std.mem.Allocator,
    items: []Record,

    pub fn deinit(self: *Records) void {
        for (self.items) |record| {
            std.crypto.secureZero(u8, record.action);
            self.allocator.free(record.action);
            std.crypto.secureZero(u8, record.payload);
            self.allocator.free(record.payload);
        }
        self.allocator.free(self.items);
        self.* = undefined;
    }
};

/// Encrypted append-only audit journal. `dir` is borrowed and must outlive the
/// Journal. The journal copies both `path` and `master_key`; `deinit` wipes its
/// key copy. All journal operations acquire an advisory file lock. The chain
/// detects corruption and reordering within the history that is present. A
/// clean removal of complete trailing frames requires an independently stored
/// tail anchor to detect and is intentionally not claimed by this module.
pub const Journal = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    path: []u8,
    key: [Aead.key_length]u8,
    session_id: SessionId,
    options: Options,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        dir: std.Io.Dir,
        path: []const u8,
        master_key: *const secret_store.MasterKey,
        session_id: SessionId,
        options: Options,
    ) !Journal {
        if (path.len == 0) return error.InvalidPath;
        if (options.max_plaintext_bytes < 8) return error.InvalidRecordLimit;
        return .{
            .allocator = allocator,
            .io = io,
            .dir = dir,
            .path = try allocator.dupe(u8, path),
            .key = master_key.value(),
            .session_id = session_id,
            .options = options,
        };
    }

    pub fn initRandomSession(
        allocator: std.mem.Allocator,
        io: std.Io,
        dir: std.Io.Dir,
        path: []const u8,
        master_key: *const secret_store.MasterKey,
        options: Options,
    ) !Journal {
        var session_id: SessionId = undefined;
        try io.randomSecure(&session_id);
        return init(allocator, io, dir, path, master_key, session_id, options);
    }

    /// Opens a persistent journal safely: an existing journal's authenticated
    /// session ID is discovered from its first frame and then verified, while
    /// a new/empty journal receives a secure random ID. Prefer this over
    /// `initRandomSession` when `path` may already exist.
    pub fn openOrCreate(
        allocator: std.mem.Allocator,
        io: std.Io,
        dir: std.Io.Dir,
        path: []const u8,
        master_key: *const secret_store.MasterKey,
        options: Options,
    ) !Journal {
        var journal = try init(allocator, io, dir, path, master_key, [_]u8{0} ** 16, options);
        errdefer journal.deinit();

        var file = try journal.openLocked();
        defer file.close(io);
        const file_length = try file.length(io);
        if (file_length == 0) {
            try io.randomSecure(&journal.session_id);
            return journal;
        }
        if (file_length < header_len) {
            _ = try recoverTail(io, file, 0, file_length, options.repair_incomplete_tail);
            try io.randomSecure(&journal.session_id);
            return journal;
        }

        var first_header: [header_len]u8 = undefined;
        if (try file.readPositionalAll(io, &first_header, 0) != first_header.len) return error.CorruptJournal;
        const decoded = decodeHeader(&first_header) catch return error.CorruptJournal;
        journal.session_id = decoded.session_id;
        _ = try journal.scanFile(file, options.repair_incomplete_tail, .none);
        return journal;
    }

    pub fn deinit(self: *Journal) void {
        std.crypto.secureZero(u8, &self.key);
        self.allocator.free(self.path);
        self.* = undefined;
    }

    /// Durable append for a completed action, decision, transcript fragment,
    /// or other non-pre-action record. Both fields are redacted before they
    /// are encrypted, and success is returned only after file sync.
    pub fn append(
        self: *Journal,
        timestamp_ns: i64,
        action: []const u8,
        payload: []const u8,
    ) !Receipt {
        return self.appendRecord(.post_action, timestamp_ns, action, payload);
    }

    /// Mandatory durable pre-action audit append. Both action and payload are
    /// redacted before encryption. Success is returned only after file sync.
    pub fn appendPreAction(
        self: *Journal,
        timestamp_ns: i64,
        action: []const u8,
        payload: []const u8,
    ) !Receipt {
        return self.appendRecord(.pre_action, timestamp_ns, action, payload);
    }

    fn appendRecord(
        self: *Journal,
        kind: RecordKind,
        timestamp_ns: i64,
        action: []const u8,
        payload: []const u8,
    ) !Receipt {
        if (!std.unicode.utf8ValidateSlice(action) or !std.unicode.utf8ValidateSlice(payload)) {
            return error.InvalidUtf8;
        }

        const safe_action = try redact.redactText(self.allocator, action);
        defer {
            std.crypto.secureZero(u8, safe_action);
            self.allocator.free(safe_action);
        }
        const safe_payload = try redact.redact(self.allocator, payload);
        defer {
            std.crypto.secureZero(u8, safe_payload);
            self.allocator.free(safe_payload);
        }

        const plaintext_len = std.math.add(usize, 8, safe_action.len) catch return error.RecordTooLarge;
        const total_plaintext_len = std.math.add(usize, plaintext_len, safe_payload.len) catch return error.RecordTooLarge;
        if (total_plaintext_len > self.options.max_plaintext_bytes or total_plaintext_len > std.math.maxInt(u32)) {
            return error.RecordTooLarge;
        }

        const plaintext = try self.allocator.alloc(u8, total_plaintext_len);
        defer {
            std.crypto.secureZero(u8, plaintext);
            self.allocator.free(plaintext);
        }
        std.mem.writeInt(u32, plaintext[0..4], @intCast(safe_action.len), .little);
        std.mem.writeInt(u32, plaintext[4..8], @intCast(safe_payload.len), .little);
        @memcpy(plaintext[8 .. 8 + safe_action.len], safe_action);
        @memcpy(plaintext[8 + safe_action.len ..], safe_payload);

        var file = try self.openLocked();
        defer file.close(self.io);
        const report = try self.scanFile(file, self.options.repair_incomplete_tail, .none);
        const sequence = std.math.add(u64, report.record_count, 1) catch return error.SequenceOverflow;
        const frame_offset = report.valid_bytes;

        var nonce: [Aead.nonce_length]u8 = undefined;
        try self.io.randomSecure(&nonce);
        var header: [header_len]u8 = undefined;
        encodeHeader(&header, .{
            .flags = switch (kind) {
                .post_action => 0,
                .pre_action => pre_action_flag,
            },
            .sequence = sequence,
            .timestamp_ns = timestamp_ns,
            .session_id = self.session_id,
            .nonce = nonce,
            .previous_hash = report.tail_hash,
            .ciphertext_len = @intCast(plaintext.len),
        });

        const frame_len = std.math.add(usize, header_len + trailer_len, plaintext.len) catch return error.RecordTooLarge;
        const frame = try self.allocator.alloc(u8, frame_len);
        defer self.allocator.free(frame);
        @memcpy(frame[0..header_len], &header);
        const ciphertext = frame[header_len .. header_len + plaintext.len];
        const tag_ptr: *[Aead.tag_length]u8 = @ptrCast(frame[header_len + plaintext.len ..][0..Aead.tag_length]);
        Aead.encrypt(ciphertext, tag_ptr, plaintext, &header, nonce, self.key);

        var chain_hash: ChainHash = undefined;
        hashFrame(frame[0 .. frame.len - Sha256.digest_length], &chain_hash);
        @memcpy(frame[frame.len - Sha256.digest_length ..], &chain_hash);

        errdefer {
            file.setLength(self.io, frame_offset) catch {};
            file.sync(self.io) catch {};
        }
        try file.writePositionalAll(self.io, frame, frame_offset);
        try file.sync(self.io);

        return .{
            .sequence = sequence,
            .kind = kind,
            .session_id = self.session_id,
            .chain_hash = chain_hash,
            .frame_offset = frame_offset,
            .frame_length = @intCast(frame.len),
        };
    }

    /// Verifies every AEAD tag, sequence number, session metadata header, and
    /// SHA-256 chain link. An incomplete final frame is truncated and synced
    /// when recovery is enabled; all other corruption is rejected.
    pub fn verify(self: *Journal) !VerifyReport {
        var file = try self.openLocked();
        defer file.close(self.io);
        return self.scanFile(file, self.options.repair_incomplete_tail, .none);
    }

    /// Decrypts the verified journal into allocator-owned records.
    pub fn show(self: *Journal, result_allocator: std.mem.Allocator) !Records {
        var list: std.ArrayList(Record) = .empty;
        errdefer deinitRecordList(result_allocator, &list);
        var file = try self.openLocked();
        defer file.close(self.io);
        _ = try self.scanFile(file, self.options.repair_incomplete_tail, .{
            .collect = .{ .allocator = result_allocator, .list = &list },
        });
        return .{ .allocator = result_allocator, .items = try list.toOwnedSlice(result_allocator) };
    }

    /// Streams verified, decrypted records as JSON Lines. Payload is exported
    /// as a string so untrusted content cannot alter the envelope. The caller
    /// controls and flushes the destination writer.
    pub fn exportJsonLines(self: *Journal, writer: *std.Io.Writer) !VerifyReport {
        var file = try self.openLocked();
        defer file.close(self.io);
        return self.scanFile(file, self.options.repair_incomplete_tail, .{ .json_lines = writer });
    }

    /// Explicitly deletes the encrypted journal. No automatic retention,
    /// pruning, or purge behavior exists. Filesystem-level secure erasure is
    /// outside this API's guarantees.
    pub fn purge(self: *Journal) !bool {
        var file = self.dir.openFile(self.io, self.path, .{
            .mode = .read_write,
            .allow_directory = false,
            .lock = .exclusive,
            .follow_symlinks = false,
            .resolve_beneath = true,
        }) catch |err| switch (err) {
            error.FileNotFound => return false,
            else => return err,
        };
        defer file.close(self.io);
        self.dir.deleteFile(self.io, self.path) catch |err| switch (err) {
            error.FileNotFound => return false,
            else => return err,
        };
        return true;
    }

    fn openLocked(self: *Journal) !std.Io.File {
        const permissions = securePermissions();
        var file = try self.dir.createFile(self.io, self.path, .{
            .read = true,
            .truncate = false,
            .lock = .exclusive,
            .permissions = permissions,
            .resolve_beneath = true,
        });
        errdefer file.close(self.io);
        if (builtin.os.tag != .windows and std.Io.File.Permissions.has_executable_bit) {
            try file.setPermissions(self.io, permissions);
        }
        return file;
    }

    fn scanFile(self: *Journal, file: std.Io.File, repair_tail: bool, sink: Sink) !VerifyReport {
        const file_length = try file.length(self.io);
        var offset: u64 = 0;
        var expected_sequence: u64 = 1;
        var previous_hash: ChainHash = zero_hash;
        var truncated_bytes: u64 = 0;

        while (offset < file_length) {
            const remaining = file_length - offset;
            if (remaining < header_len) {
                truncated_bytes = try recoverTail(self.io, file, offset, file_length, repair_tail);
                break;
            }

            var header: [header_len]u8 = undefined;
            if (try file.readPositionalAll(self.io, &header, offset) != header.len) return error.CorruptJournal;
            const decoded = decodeHeader(&header) catch return error.CorruptJournal;
            if (decoded.flags & ~known_flags != 0) return error.CorruptJournal;
            if (decoded.sequence != expected_sequence) return error.CorruptJournal;
            if (!std.crypto.timing_safe.eql(SessionId, self.session_id, decoded.session_id)) return error.CorruptJournal;
            if (!std.crypto.timing_safe.eql(ChainHash, previous_hash, decoded.previous_hash)) return error.CorruptJournal;
            if (decoded.ciphertext_len < 8 or decoded.ciphertext_len > self.options.max_plaintext_bytes) {
                return error.CorruptJournal;
            }

            const frame_len = std.math.add(u64, header_len + trailer_len, decoded.ciphertext_len) catch return error.CorruptJournal;
            if (frame_len > remaining) {
                truncated_bytes = try recoverTail(self.io, file, offset, file_length, repair_tail);
                break;
            }

            const body_len: usize = @intCast(decoded.ciphertext_len + trailer_len);
            const body = try self.allocator.alloc(u8, body_len);
            defer self.allocator.free(body);
            if (try file.readPositionalAll(self.io, body, offset + header_len) != body.len) return error.CorruptJournal;

            const ciphertext_len: usize = @intCast(decoded.ciphertext_len);
            const ciphertext = body[0..ciphertext_len];
            const tag: [Aead.tag_length]u8 = body[ciphertext_len..][0..Aead.tag_length].*;
            const stored_hash: ChainHash = body[ciphertext_len + Aead.tag_length ..][0..Sha256.digest_length].*;

            var computed_hash_state = Sha256.init(.{});
            computed_hash_state.update(&header);
            computed_hash_state.update(ciphertext);
            computed_hash_state.update(&tag);
            var computed_hash: ChainHash = undefined;
            computed_hash_state.final(&computed_hash);
            if (!std.crypto.timing_safe.eql(ChainHash, computed_hash, stored_hash)) return error.CorruptJournal;

            const plaintext = try self.allocator.alloc(u8, ciphertext_len);
            defer {
                std.crypto.secureZero(u8, plaintext);
                self.allocator.free(plaintext);
            }
            Aead.decrypt(plaintext, ciphertext, tag, &header, decoded.nonce, self.key) catch return error.CorruptJournal;
            const plain = decodePlaintext(plaintext) catch return error.CorruptJournal;
            if (!std.unicode.utf8ValidateSlice(plain.action) or !std.unicode.utf8ValidateSlice(plain.payload)) {
                return error.CorruptJournal;
            }

            try emitRecord(sink, .{
                .sequence = decoded.sequence,
                .kind = if (decoded.flags & pre_action_flag != 0) .pre_action else .post_action,
                .timestamp_ns = decoded.timestamp_ns,
                .session_id = decoded.session_id,
                .action = plain.action,
                .payload = plain.payload,
                .chain_hash = computed_hash,
            });

            previous_hash = computed_hash;
            expected_sequence = std.math.add(u64, expected_sequence, 1) catch return error.CorruptJournal;
            offset = std.math.add(u64, offset, frame_len) catch return error.CorruptJournal;
        }

        return .{
            .record_count = expected_sequence - 1,
            .valid_bytes = offset,
            .truncated_bytes = truncated_bytes,
            .tail_hash = previous_hash,
        };
    }
};

const Header = struct {
    flags: u16,
    sequence: u64,
    timestamp_ns: i64,
    session_id: SessionId,
    nonce: [Aead.nonce_length]u8,
    previous_hash: ChainHash,
    ciphertext_len: u32,
};

const Plaintext = struct {
    action: []const u8,
    payload: []const u8,
};

const RecordView = struct {
    sequence: u64,
    kind: RecordKind,
    timestamp_ns: i64,
    session_id: SessionId,
    action: []const u8,
    payload: []const u8,
    chain_hash: ChainHash,
};

const Sink = union(enum) {
    none,
    collect: struct {
        allocator: std.mem.Allocator,
        list: *std.ArrayList(Record),
    },
    json_lines: *std.Io.Writer,
};

fn encodeHeader(output: *[header_len]u8, header: Header) void {
    @memcpy(output[0..8], &magic);
    std.mem.writeInt(u16, output[8..10], format_version, .little);
    std.mem.writeInt(u16, output[10..12], header.flags, .little);
    std.mem.writeInt(u64, output[12..20], header.sequence, .little);
    std.mem.writeInt(u64, output[20..28], @bitCast(header.timestamp_ns), .little);
    @memcpy(output[28..44], &header.session_id);
    @memcpy(output[44..68], &header.nonce);
    @memcpy(output[68..100], &header.previous_hash);
    std.mem.writeInt(u32, output[100..104], header.ciphertext_len, .little);
}

fn decodeHeader(input: *const [header_len]u8) !Header {
    if (!std.mem.eql(u8, input[0..8], &magic)) return error.InvalidMagic;
    if (std.mem.readInt(u16, input[8..10], .little) != format_version) return error.UnsupportedVersion;
    return .{
        .flags = std.mem.readInt(u16, input[10..12], .little),
        .sequence = std.mem.readInt(u64, input[12..20], .little),
        .timestamp_ns = @bitCast(std.mem.readInt(u64, input[20..28], .little)),
        .session_id = input[28..44].*,
        .nonce = input[44..68].*,
        .previous_hash = input[68..100].*,
        .ciphertext_len = std.mem.readInt(u32, input[100..104], .little),
    };
}

fn decodePlaintext(input: []const u8) !Plaintext {
    if (input.len < 8) return error.InvalidPlaintext;
    const action_len: usize = std.mem.readInt(u32, input[0..4], .little);
    const payload_len: usize = std.mem.readInt(u32, input[4..8], .little);
    const action_end = std.math.add(usize, 8, action_len) catch return error.InvalidPlaintext;
    const payload_end = std.math.add(usize, action_end, payload_len) catch return error.InvalidPlaintext;
    if (payload_end != input.len) return error.InvalidPlaintext;
    return .{ .action = input[8..action_end], .payload = input[action_end..payload_end] };
}

fn hashFrame(input: []const u8, output: *ChainHash) void {
    Sha256.hash(input, output, .{});
}

fn recoverTail(io: std.Io, file: std.Io.File, valid_length: u64, file_length: u64, repair: bool) !u64 {
    if (!repair) return error.IncompleteFinalFrame;
    try file.setLength(io, valid_length);
    try file.sync(io);
    return file_length - valid_length;
}

fn emitRecord(sink: Sink, record: RecordView) !void {
    switch (sink) {
        .none => {},
        .collect => |target| {
            const action = try target.allocator.dupe(u8, record.action);
            errdefer target.allocator.free(action);
            const payload = try target.allocator.dupe(u8, record.payload);
            errdefer target.allocator.free(payload);
            try target.list.append(target.allocator, .{
                .sequence = record.sequence,
                .kind = record.kind,
                .timestamp_ns = record.timestamp_ns,
                .session_id = record.session_id,
                .action = action,
                .payload = payload,
                .chain_hash = record.chain_hash,
            });
        },
        .json_lines => |writer| {
            const session_hex = std.fmt.bytesToHex(record.session_id, .lower);
            const hash_hex = std.fmt.bytesToHex(record.chain_hash, .lower);
            const exported = .{
                .sequence = record.sequence,
                .kind = @tagName(record.kind),
                .timestamp_ns = record.timestamp_ns,
                .session_id = session_hex[0..],
                .action = record.action,
                .payload = record.payload,
                .chain_hash = hash_hex[0..],
            };
            try writer.print("{f}\n", .{std.json.fmt(exported, .{})});
        },
    }
}

fn deinitRecordList(allocator: std.mem.Allocator, list: *std.ArrayList(Record)) void {
    for (list.items) |record| {
        std.crypto.secureZero(u8, record.action);
        allocator.free(record.action);
        std.crypto.secureZero(u8, record.payload);
        allocator.free(record.payload);
    }
    list.deinit(allocator);
}

fn securePermissions() std.Io.File.Permissions {
    return switch (builtin.os.tag) {
        .linux, .macos, .freebsd, .netbsd, .openbsd, .dragonfly, .illumos => std.Io.File.Permissions.fromMode(0o600),
        else => .default_file,
    };
}

test "journal encrypts redacted records verifies shows exports and purges" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var master_key = secret_store.MasterKey.init([_]u8{0x42} ** secret_store.key_length);
    defer master_key.deinit();
    const session = [_]u8{0x11} ** 16;
    var journal = try Journal.init(std.testing.allocator, std.testing.io, tmp.dir, "audit.journal", &master_key, session, .{});
    defer journal.deinit();

    const first = try journal.appendPreAction(100, "call-api sk-abcdefghijklmnopqrstuvwxyz", "{\"authorization\":\"Bearer top-secret-value\",\"safe\":true}");
    const second = try journal.append(200, "second", "password=hunter2");
    try std.testing.expectEqual(@as(u64, 1), first.sequence);
    try std.testing.expectEqual(@as(u64, 2), second.sequence);
    try std.testing.expectEqual(RecordKind.pre_action, first.kind);
    try std.testing.expectEqual(RecordKind.post_action, second.kind);

    const on_disk = try tmp.dir.readFileAlloc(std.testing.io, "audit.journal", std.testing.allocator, .limited(64 * 1024));
    defer std.testing.allocator.free(on_disk);
    for ([_][]const u8{ "top-secret-value", "hunter2", "sk-abcdefghijklmnopqrstuvwxyz", redact.marker }) |plaintext| {
        try std.testing.expect(std.mem.indexOf(u8, on_disk, plaintext) == null);
    }

    const report = try journal.verify();
    try std.testing.expectEqual(@as(u64, 2), report.record_count);
    try std.testing.expectEqual(@as(u64, 0), report.truncated_bytes);

    var records = try journal.show(std.testing.allocator);
    defer records.deinit();
    try std.testing.expectEqual(@as(usize, 2), records.items.len);
    try std.testing.expectEqual(RecordKind.pre_action, records.items[0].kind);
    try std.testing.expectEqual(RecordKind.post_action, records.items[1].kind);
    try std.testing.expect(std.mem.indexOf(u8, records.items[0].action, redact.marker) != null);
    try std.testing.expect(std.mem.indexOf(u8, records.items[0].payload, "top-secret-value") == null);
    try std.testing.expect(std.mem.indexOf(u8, records.items[1].payload, "hunter2") == null);

    var exported: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer exported.deinit();
    const export_report = try journal.exportJsonLines(&exported.writer);
    try std.testing.expectEqual(@as(u64, 2), export_report.record_count);
    try std.testing.expect(std.mem.indexOf(u8, exported.written(), "\"sequence\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported.written(), "\"kind\":\"pre_action\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported.written(), "\"kind\":\"post_action\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported.written(), "top-secret-value") == null);

    try std.testing.expect(try journal.purge());
    try std.testing.expect(!try journal.purge());
}

test "incomplete final frame is truncated while valid history remains" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var master_key = secret_store.MasterKey.init([_]u8{0x24} ** secret_store.key_length);
    defer master_key.deinit();
    var journal = try Journal.init(std.testing.allocator, std.testing.io, tmp.dir, "recover.journal", &master_key, [_]u8{7} ** 16, .{});
    defer journal.deinit();

    const first = try journal.appendPreAction(1, "first", "one");
    const second = try journal.appendPreAction(2, "second", "two");
    var file = try tmp.dir.openFile(std.testing.io, "recover.journal", .{ .mode = .read_write });
    try file.setLength(std.testing.io, second.frame_offset + second.frame_length - 5);
    try file.sync(std.testing.io);
    file.close(std.testing.io);

    const report = try journal.verify();
    try std.testing.expectEqual(@as(u64, 1), report.record_count);
    try std.testing.expectEqual(first.frame_length, report.valid_bytes);
    try std.testing.expect(report.truncated_bytes > 0);

    var records = try journal.show(std.testing.allocator);
    defer records.deinit();
    try std.testing.expectEqual(@as(usize, 1), records.items.len);
    try std.testing.expectEqualStrings("first", records.items[0].action);
}

test "ciphertext corruption and header reordering are rejected" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var master_key = secret_store.MasterKey.init([_]u8{0x66} ** secret_store.key_length);
    defer master_key.deinit();
    var journal = try Journal.init(std.testing.allocator, std.testing.io, tmp.dir, "tamper.journal", &master_key, [_]u8{3} ** 16, .{});
    defer journal.deinit();

    _ = try journal.appendPreAction(1, "first", "payload");
    var file = try tmp.dir.openFile(std.testing.io, "tamper.journal", .{ .mode = .read_write });
    var byte: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try file.readPositionalAll(std.testing.io, &byte, header_len));
    byte[0] ^= 0x80;
    try file.writePositionalAll(std.testing.io, &byte, header_len);
    try file.sync(std.testing.io);
    file.close(std.testing.io);
    try std.testing.expectError(error.CorruptJournal, journal.verify());
}

test "journal rejects an authenticated record from another session" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var master_key = secret_store.MasterKey.init([_]u8{0x67} ** secret_store.key_length);
    defer master_key.deinit();
    var writer = try Journal.init(std.testing.allocator, std.testing.io, tmp.dir, "session.journal", &master_key, [_]u8{3} ** 16, .{});
    defer writer.deinit();
    _ = try writer.append(1, "result", "payload");

    var wrong_session = try Journal.init(std.testing.allocator, std.testing.io, tmp.dir, "session.journal", &master_key, [_]u8{4} ** 16, .{});
    defer wrong_session.deinit();
    try std.testing.expectError(error.CorruptJournal, wrong_session.verify());
}

test "openOrCreate reuses the authenticated session of a persistent journal" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var master_key = secret_store.MasterKey.init([_]u8{0x68} ** secret_store.key_length);
    defer master_key.deinit();

    var created = try Journal.openOrCreate(std.testing.allocator, std.testing.io, tmp.dir, "persistent.journal", &master_key, .{});
    const created_session = created.session_id;
    _ = try created.append(1, "decision", "accepted");
    created.deinit();

    var reopened = try Journal.openOrCreate(std.testing.allocator, std.testing.io, tmp.dir, "persistent.journal", &master_key, .{});
    defer reopened.deinit();
    try std.testing.expectEqualSlices(u8, &created_session, &reopened.session_id);
    try std.testing.expectEqual(@as(u64, 1), (try reopened.verify()).record_count);
}

fn journalInitAllocationCase(allocator: std.mem.Allocator, dir: std.Io.Dir, key: *const secret_store.MasterKey) !void {
    var journal = try Journal.init(allocator, std.testing.io, dir, "allocation.journal", key, [_]u8{1} ** 16, .{});
    defer journal.deinit();
}

test "journal initialization propagates allocation failure" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var master_key = secret_store.MasterKey.init([_]u8{0x99} ** secret_store.key_length);
    defer master_key.deinit();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, journalInitAllocationCase, .{ tmp.dir, &master_key });
}

const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");
const audit = @import("audit.zig");
const app_server = @import("app_server.zig");
const cli = @import("cli.zig");
const codex_exec = @import("codex_exec.zig");
const config = @import("config.zig");
const events = @import("events.zig");
const exit_codes = @import("exit_codes.zig");
const policy = @import("policy.zig");
const preflight = @import("preflight.zig");
const process_runner = @import("process_runner.zig");
const redact = @import("redact.zig");
const secret_store = @import("secret_store.zig");
const state_paths = @import("state_paths.zig");

const max_prompt_bytes = preflight.max_prompt_bytes;
// Postflight receives a recent evidence window while every complete redacted
// backend event is durably persisted as its own encrypted audit record.
const max_evidence_bytes: usize = 64 * 1024;
// `jev-decide` owns the real connect/request deadlines and retry policy. This
// outer watchdog is only a final containment bound, so it must exceed the
// companion's largest accepted configuration (three circuit-bounded attempts,
// including connect, request, and Retry-After time).
const jev_process_watchdog_ms: u64 = 6 * 60 * 60 * 1000;

pub fn run(init: std.process.Init, stdout: *std.Io.Writer, stderr: *std.Io.Writer) !u8 {
    const allocator = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const invocation = cli.parse(args) catch |err| {
        try stderr.print("jevx: {s}\n\n", .{@errorName(err)});
        try printHelp(stderr);
        return exit_codes.usage;
    };

    if (invocation.command == .help) {
        try printHelp(stdout);
        return exit_codes.success;
    }

    const workspace = canonicalWorkspace(allocator, init.io, init.environ_map, invocation.options.workspace) catch |err| {
        try stderr.print("jevx: workspace resolution failed: {s}\n", .{@errorName(err)});
        return err;
    };
    defer allocator.free(workspace);
    const effective = loadEffectiveConfig(init.arena.allocator(), init.io, init.environ_map, workspace, invocation.options) catch |err| {
        try stderr.print("jevx: configuration load failed: {s}\n", .{@errorName(err)});
        return err;
    };
    const binaries = BinaryPaths.resolve(allocator, init.io, effective.codex_bin, effective.jev_bin) catch |err| {
        try stderr.print("jevx: executable discovery failed: {s}\n", .{@errorName(err)});
        return err;
    };
    defer binaries.deinit(allocator);

    var event_bytes: [16]u8 = undefined;
    try init.io.randomSecure(&event_bytes);
    const event_session = std.fmt.bytesToHex(event_bytes, .lower);
    var emitter: events.Emitter = .{
        .writer = stdout,
        .io = init.io,
        .session_id = &event_session,
    };

    var runtime: Runtime = .{
        .allocator = allocator,
        .io = init.io,
        .environ = init.environ_map,
        .stdout = stdout,
        .stderr = stderr,
        .json = invocation.options.json,
        .workspace = workspace,
        .config = effective,
        .binaries = binaries,
        .emitter = &emitter,
    };

    if (runtime.json) {
        try runtime.emitter.emit(.session_started, .{
            .version = root.version,
            .backend = @tagName(effective.backend),
            .policy = @tagName(effective.policy_name),
        });
    }

    return switch (invocation.command) {
        .help => unreachable,
        .version => runtime.printVersion(),
        .policy_explain => runtime.explainPolicy(),
        .doctor => runtime.doctor(),
        .setup => runtime.setup(),
        .decide => runtime.decide(),
        .audit => |action| runtime.auditCommand(action, invocation.options.yes),
        .run => runtime.runOnce(null, invocation.options.prompt_file),
        .resume_ => |thread_id| runtime.runOnce(thread_id, invocation.options.prompt_file),
        .repl => runtime.repl(),
    };
}

pub fn classifyError(err: anyerror) u8 {
    return switch (err) {
        error.FileNotFound,
        error.MissingDependency,
        error.InvalidExecutable,
        error.UnsupportedSecretStore,
        => exit_codes.dependency,
        error.CredentialUnavailable,
        error.SecretNotFound,
        error.AuthenticationFailed,
        => exit_codes.authentication,
        error.PolicyDenied,
        error.ConfirmationRequired,
        error.StateDirectoryMustBeAbsolute,
        error.InvalidConfig,
        error.InvalidEnvironment,
        error.WorkspaceTooBroad,
        error.PostflightFailed,
        => exit_codes.policy,
        error.ProcessTimeout,
        error.CircuitOpen,
        error.TransportFailed,
        => exit_codes.transient,
        error.MalformedJson,
        error.InvalidJson,
        error.InvalidDecisionRequest,
        error.DecisionProviderRejected,
        error.ProtocolEnded,
        error.RpcError,
        error.DuplicateJsonField,
        error.TruncatedJson,
        error.EmptyResponse,
        error.MultipleResponses,
        => exit_codes.protocol,
        error.AuditUnavailable,
        error.AuthenticationFailedAudit,
        error.CorruptJournal,
        => exit_codes.audit,
        else => exit_codes.agent,
    };
}

const Runtime = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    environ: *std.process.Environ.Map,
    stdout: *std.Io.Writer,
    stderr: *std.Io.Writer,
    json: bool,
    workspace: []const u8,
    config: config.Value,
    binaries: BinaryPaths,
    emitter: *events.Emitter,

    fn printVersion(self: *Runtime) !u8 {
        if (self.json) {
            try self.emitter.emit(.completed, .{
                .version = root.version,
                .zig = "0.16.0",
                .codex_bundle = "rust-v0.156.1",
                .unofficial = true,
            });
        } else {
            try self.stdout.print("jevx {s} (Zig 0.16.0; Codex rust-v0.156.1)\n", .{root.version});
        }
        return exit_codes.success;
    }

    fn explainPolicy(self: *Runtime) !u8 {
        const thresholds = policy.Thresholds.forPolicy(self.config.policy_name);
        if (self.json) {
            try self.emitter.emit(.policy_result, .{
                .profile = @tagName(self.config.policy_name),
                .thresholds = thresholds,
                .always_confirm = "push,release,deploy,message,purchase,account-change,destructive,privilege,credential,outside-workspace,network,unknown",
                .hard_deny = "credential-exfiltration,sandbox-bypass,policy-tampering,broad-destructive",
            });
        } else {
            try self.stdout.print(
                \\Policy: {s}
                \\Automatic action requires route >= {d:.2}, impact < {d:.2}, impact confidence >= {d:.2}, hazards < {d:.2}, underspecification < {d:.2}.
                \\Always confirm: pushes, releases, deployments, messages, purchases, account changes, destructive operations, privilege changes, credential access, writes outside the workspace, network access, and unknown intent.
                \\Hard deny: credential exfiltration, sandbox bypass, policy tampering, and broad destructive commands.
                \\Project policy may tighten but never relax this policy. No flag bypasses immutable guards.
                \\
            , .{ @tagName(self.config.policy_name), thresholds.route, thresholds.impact, thresholds.impact_confidence, thresholds.hazard, thresholds.underspecified });
        }
        return exit_codes.success;
    }

    fn doctor(self: *Runtime) !u8 {
        var codex_env = try safeCodexEnvironment(self.allocator, self.environ);
        defer codex_env.deinit();
        const codex_version = commandProbe(self.allocator, self.io, &.{ self.binaries.codex, "--version" }, &codex_env, "0.156.1") catch false;
        const codex_auth = commandProbe(self.allocator, self.io, &.{ self.binaries.codex, "login", "status" }, &codex_env, "Logged in") catch false;
        var jev_env = try jevEnvironment(self.allocator, self.environ);
        defer wipeEnvironment(&jev_env);
        const jev_auth = commandProbe(self.allocator, self.io, &.{ self.binaries.jev, "--health" }, &jev_env, "\"ok\":true") catch false;

        var audit_key_ok = false;
        var journal_ok = false;
        var key = secret_store.load(self.allocator, self.io, .{ .environ_map = self.environ }) catch null;
        if (key) |*actual| {
            defer actual.deinit();
            audit_key_ok = true;
            var paths = state_paths.resolve(self.allocator, self.environ) catch null;
            if (paths) |*actual_paths| {
                defer actual_paths.deinit();
                if (std.Io.Dir.accessAbsolute(self.io, actual_paths.journal, .{})) |_| {
                    var state_dir = std.Io.Dir.openDirAbsolute(self.io, actual_paths.state_dir, .{}) catch null;
                    if (state_dir) |*actual_dir| {
                        defer actual_dir.close(self.io);
                        var journal = audit.Journal.openOrCreate(self.allocator, self.io, actual_dir.*, state_paths.journal_name, actual, .{}) catch null;
                        if (journal) |*actual_journal| {
                            defer actual_journal.deinit();
                            if (actual_journal.verify()) |_| journal_ok = true else |_| {}
                        }
                    }
                } else |_| {}
            }
        }

        const ok = codex_version and codex_auth and jev_auth and audit_key_ok and journal_ok;
        if (self.json) {
            try self.emitter.emit(.completed, .{
                .ok = ok,
                .codex_version = codex_version,
                .codex_auth = codex_auth,
                .jev_auth = jev_auth,
                .audit_key = audit_key_ok,
                .journal = journal_ok,
                .codex_bin = self.binaries.codex,
                .jev_bin = self.binaries.jev,
            });
        } else {
            try self.stdout.print(
                "Codex 0.156.1: {s}\nCodex ChatGPT auth: {s}\nJev credential: {s}\nAudit key: {s}\nAudit journal: {s}\n",
                .{ mark(codex_version), mark(codex_auth), mark(jev_auth), mark(audit_key_ok), mark(journal_ok) },
            );
        }
        return if (ok) exit_codes.success else exit_codes.dependency;
    }

    fn setup(self: *Runtime) !u8 {
        const interactive = std.Io.File.stdin().isTty(self.io) catch false;
        var codex_env = try safeCodexEnvironment(self.allocator, self.environ);
        defer codex_env.deinit();
        var codex_auth = commandProbe(self.allocator, self.io, &.{ self.binaries.codex, "login", "status" }, &codex_env, "Logged in") catch false;
        if (!codex_auth) {
            if (!interactive) return error.AuthenticationFailed;
            try self.stderr.writeAll("Codex authentication is required; opening `codex login`.\n");
            var child = try std.process.spawn(self.io, .{
                .argv = &.{ self.binaries.codex, "login" },
                .environ_map = &codex_env,
                .stdin = .inherit,
                .stdout = .inherit,
                .stderr = .inherit,
            });
            const term = try child.wait(self.io);
            codex_auth = switch (term) {
                .exited => |status| status == 0,
                else => false,
            };
            if (!codex_auth) return error.AuthenticationFailed;
        }

        var jev_env = try jevEnvironment(self.allocator, self.environ);
        defer wipeEnvironment(&jev_env);
        const jev_installed = commandProbe(
            self.allocator,
            self.io,
            &.{ self.binaries.jev, "--help" },
            &jev_env,
            "jev-decide",
        ) catch false;
        if (!jev_installed) return error.MissingDependency;
        var jev_auth = commandProbe(
            self.allocator,
            self.io,
            &.{ self.binaries.jev, "--health" },
            &jev_env,
            "\"ok\":true",
        ) catch false;
        if (!jev_auth) {
            if (builtin.os.tag == .linux) {
                try self.stderr.writeAll("Linux keeps the OpenRouter key session-only. Export OPENROUTER_API_KEY and rerun `jevx setup`.\n");
                return error.CredentialUnavailable;
            }
            if (!interactive) return error.CredentialUnavailable;
            const api_key = try secret_store.Prompt.tty().read(self.allocator, self.io, "OpenRouter API key (stored in the native credential manager): ");
            defer {
                std.crypto.secureZero(u8, api_key);
                self.allocator.free(api_key);
            }
            try self.storeJevCredential(api_key, &jev_env);
            jev_auth = commandProbe(
                self.allocator,
                self.io,
                &.{ self.binaries.jev, "--health" },
                &jev_env,
                "\"ok\":true",
            ) catch false;
            if (!jev_auth) return error.AuthenticationFailed;
        }

        const safe_prompt = "Classify this read-only setup smoke test.";
        const request = try preflight.build(self.allocator, safe_prompt, self.workspace, null);
        defer self.allocator.free(request);
        const response = try self.invokeJev(request);
        defer self.allocator.free(response);
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const parsed = try preflight.parseLeaky(arena.allocator(), response);

        var paths = try state_paths.resolve(self.allocator, self.environ);
        defer paths.deinit();
        try paths.ensure(self.io);
        var key = try secret_store.loadOrCreate(self.allocator, self.io, .{
            .prompt = if (interactive) secret_store.Prompt.tty() else null,
            .environ_map = self.environ,
        });
        defer key.deinit();
        var state_dir = try std.Io.Dir.openDirAbsolute(self.io, paths.state_dir, .{});
        defer state_dir.close(self.io);
        var journal = try audit.Journal.openOrCreate(self.allocator, self.io, state_dir, state_paths.journal_name, &key, .{});
        defer journal.deinit();
        const payload = try jsonOwned(self.allocator, .{ .jev_model = parsed.resolved_model, .codex_authenticated = true });
        defer self.allocator.free(payload);
        _ = try journal.append(nowNs(self.io), "setup.completed", payload);

        if (self.json) {
            try self.emitter.emit(.completed, .{ .ok = true, .jev_model = parsed.resolved_model });
        } else {
            try self.stdout.print("Setup complete. Codex is authenticated, Jev answered as {s}, and the audit key is available.\n", .{parsed.resolved_model});
        }
        return exit_codes.success;
    }

    fn storeJevCredential(self: *Runtime, key: []const u8, environment: *const std.process.Environ.Map) !void {
        var result = try process_runner.run(self.allocator, self.io, .{
            .argv = &.{ self.binaries.jev, "--store-key" },
            .environ_map = environment,
            .environment_policy = .exact,
            .stdin_data = key,
            .limits = .{
                .max_input_bytes = 4096,
                .max_line_bytes = 4096,
                .max_stdout_bytes = 4096,
                .max_stderr_bytes = 16 * 1024,
                .max_stderr_capture_bytes = 1024,
                .max_events = 1,
                .timeout_ms = 30_000,
            },
        });
        defer result.deinit(self.allocator);
        if (!result.succeeded()) return jevTermError(result.term);
    }

    fn decide(self: *Runtime) !u8 {
        const input = try readStdin(self.allocator, self.io, 1024 * 1024);
        defer self.allocator.free(input);
        const response = try self.invokeJev(input);
        defer self.allocator.free(response);
        try self.stdout.writeAll(response);
        try self.stdout.writeByte('\n');
        return exit_codes.success;
    }

    fn auditCommand(self: *Runtime, action: cli.AuditAction, yes: bool) !u8 {
        const interactive = std.Io.File.stdin().isTty(self.io) catch false;
        var paths = try state_paths.resolve(self.allocator, self.environ);
        defer paths.deinit();
        try paths.ensure(self.io);
        var key = try secret_store.load(self.allocator, self.io, .{
            .prompt = if (interactive) secret_store.Prompt.tty() else null,
            .environ_map = self.environ,
        });
        defer key.deinit();
        var state_dir = try std.Io.Dir.openDirAbsolute(self.io, paths.state_dir, .{});
        defer state_dir.close(self.io);
        var journal = try audit.Journal.openOrCreate(self.allocator, self.io, state_dir, state_paths.journal_name, &key, .{});
        defer journal.deinit();

        switch (action) {
            .verify => {
                const report = try journal.verify();
                if (self.json) {
                    try self.emitter.emit(.completed, .{ .valid = true, .records = report.record_count, .truncated_bytes = report.truncated_bytes });
                } else {
                    try self.stdout.print("Audit valid: {d} records, {d} recovered tail bytes.\n", .{ report.record_count, report.truncated_bytes });
                }
            },
            .export_ => _ = try journal.exportJsonLines(self.stdout),
            .show => {
                var records = try journal.show(self.allocator);
                defer records.deinit();
                for (records.items) |record| {
                    if (self.json) {
                        try self.emitter.emit(.audit_recorded, .{ .sequence = record.sequence, .kind = @tagName(record.kind), .action = record.action, .payload = record.payload });
                    } else {
                        try self.stdout.print("#{d} {s} {s}\n{s}\n", .{ record.sequence, @tagName(record.kind), record.action, record.payload });
                    }
                }
            },
            .purge => {
                if (!yes) {
                    try self.stderr.writeAll("Refusing audit purge without the explicit `audit purge --yes` confirmation.\n");
                    return exit_codes.policy;
                }
                const removed = try journal.purge();
                if (self.json) try self.emitter.emit(.completed, .{ .purged = removed }) else try self.stdout.print("Audit journal purged: {}\n", .{removed});
            },
        }
        return exit_codes.success;
    }

    fn runOnce(self: *Runtime, resume_thread_id: ?[]const u8, prompt_file: ?[]const u8) !u8 {
        const prompt = if (prompt_file) |path|
            try readFileBounded(self.allocator, self.io, path, max_prompt_bytes)
        else
            try readStdin(self.allocator, self.io, max_prompt_bytes);
        defer self.allocator.free(prompt);
        if (std.mem.trim(u8, prompt, " \t\r\n").len == 0) return error.EmptyPrompt;
        const interactive = prompt_file != null and (std.Io.File.stdin().isTty(self.io) catch false) and !self.json;
        var outcome = try self.executeTurn(prompt, resume_thread_id, interactive);
        defer outcome.deinit(self.allocator);
        return if (outcome.succeeded) exit_codes.success else exit_codes.agent;
    }

    fn repl(self: *Runtime) !u8 {
        const tty = std.Io.File.stdin().isTty(self.io) catch false;
        if (!tty) return self.runOnce(null, null);
        var input_buffer: [64 * 1024]u8 = undefined;
        var reader = std.Io.File.stdin().readerStreaming(self.io, &input_buffer);
        var thread_id: ?[]u8 = null;
        defer if (thread_id) |id| self.allocator.free(id);
        if (!self.json) try self.stdout.writeAll("jevx REPL. Use :quit to exit or :new to start a new Codex thread.\n");
        while (true) {
            if (!self.json) {
                try self.stdout.writeAll("jevx> ");
                try self.stdout.flush();
            }
            const maybe_line = try reader.interface.takeDelimiter('\n');
            const line = maybe_line orelse break;
            const prompt = std.mem.trim(u8, line, " \t\r\n");
            if (prompt.len == 0) continue;
            if (std.mem.eql(u8, prompt, ":quit") or std.mem.eql(u8, prompt, ":q")) break;
            if (std.mem.eql(u8, prompt, ":new")) {
                if (thread_id) |id| self.allocator.free(id);
                thread_id = null;
                continue;
            }
            var outcome = self.executeTurn(prompt, thread_id, true) catch |err| {
                try self.stderr.print("turn failed: {s}\n", .{@errorName(err)});
                continue;
            };
            defer outcome.deinit(self.allocator);
            if (outcome.thread_id) |new_id| {
                if (thread_id) |old| self.allocator.free(old);
                thread_id = try self.allocator.dupe(u8, new_id);
            }
        }
        return exit_codes.success;
    }

    fn executeTurn(self: *Runtime, prompt: []const u8, resume_thread_id: ?[]const u8, interactive: bool) !TurnOutcome {
        var turn_bytes: [16]u8 = undefined;
        try self.io.randomSecure(&turn_bytes);
        const event_turn = std.fmt.bytesToHex(turn_bytes, .lower);
        self.emitter.turn_id = &event_turn;
        defer self.emitter.turn_id = null;

        // Semantic routing is advisory. Immutable literal guards always run
        // before Jev, journaling setup, or any Codex backend can see the prompt.
        if (policy.guardText(prompt)) |guard_reason| {
            if (self.json) {
                try self.emitter.emit(.policy_result, .{
                    .disposition = "deny",
                    .reason = "hard_guard",
                    .guard = @tagName(guard_reason),
                });
            } else {
                try self.stderr.print("policy denied request ({s}).\n", .{@tagName(guard_reason)});
            }
            return error.PolicyDenied;
        }

        var paths = try state_paths.resolve(self.allocator, self.environ);
        defer paths.deinit();
        try paths.ensure(self.io);
        var key = try secret_store.loadOrCreate(self.allocator, self.io, .{
            .prompt = if (interactive) secret_store.Prompt.tty() else null,
            .environ_map = self.environ,
        });
        defer key.deinit();
        var state_dir = try std.Io.Dir.openDirAbsolute(self.io, paths.state_dir, .{});
        defer state_dir.close(self.io);
        var journal = try audit.Journal.openOrCreate(self.allocator, self.io, state_dir, state_paths.journal_name, &key, .{});
        defer journal.deinit();

        const redacted_prompt = try redact.redact(self.allocator, prompt);
        defer self.allocator.free(redacted_prompt);
        const request = try preflight.build(self.allocator, redacted_prompt, self.workspace, null);
        defer self.allocator.free(request);

        var decision_arena = std.heap.ArenaAllocator.init(self.allocator);
        defer decision_arena.deinit();
        const response = self.invokeJev(request) catch |err| {
            const unavailable_payload = try jsonOwned(self.allocator, .{
                .disposition = "deny",
                .reason = "jev_unavailable",
                .error_class = @errorName(err),
            });
            defer self.allocator.free(unavailable_payload);
            _ = try journal.append(nowNs(self.io), "decision.unavailable", unavailable_payload);
            if (self.json) {
                try self.emitter.emit(.policy_result, .{
                    .disposition = "deny",
                    .reason = "jev_unavailable",
                });
            } else {
                try self.stderr.print("policy denied agent turn because Jev is unavailable ({s}).\n", .{@errorName(err)});
            }
            return err;
        };
        defer self.allocator.free(response);
        const parsed = try preflight.parseLeaky(decision_arena.allocator(), response);
        const assessment = parsed.assessment;
        const resolved_model = parsed.resolved_model;

        var evaluation = policy.evaluate(self.config.policy_name, assessment, interactive);
        var confirmation_declined = false;
        if (evaluation.disposition == .require_confirmation) {
            if (!try askConfirmation(self.io, self.stdout, "Policy requires confirmation. Continue this turn? [y/N] ")) {
                evaluation.disposition = .deny;
                confirmation_declined = true;
            } else {
                evaluation.disposition = .auto_allow;
            }
        }

        // v0.1 ships an empty enforceable domain allowlist. The Codex parent
        // can reach its own API, but model-generated network activity remains
        // disabled even when an interactive user confirms the semantic class.
        if (assessment.action == .network) {
            evaluation = .{ .disposition = .deny, .reason = .network_disabled };
        }

        const mutating = policy.isMutation(assessment.action) and evaluation.disposition != .read_only_only;
        if (resume_thread_id) |thread_id| {
            if (mutating or !try resumeThreadAllowed(self.allocator, &journal, thread_id, self.workspace)) {
                evaluation = .{ .disposition = .deny, .reason = .unsafe_resume };
            }
        }
        if (self.json) {
            try self.emitter.emit(.policy_result, .{
                .disposition = @tagName(evaluation.disposition),
                .reason = @tagName(evaluation.reason),
                .action = @tagName(assessment.action),
                .jev_model = resolved_model,
            });
        } else {
            try self.stderr.print("policy: {s} ({s}, {s})\n", .{ @tagName(evaluation.disposition), @tagName(assessment.action), @tagName(evaluation.reason) });
        }
        if (evaluation.disposition == .deny or confirmation_declined) return error.PolicyDenied;

        const decision_payload = try jsonOwned(self.allocator, .{
            .action = @tagName(assessment.action),
            .disposition = @tagName(evaluation.disposition),
            .reason = @tagName(evaluation.reason),
            .jev_model = resolved_model,
        });
        defer self.allocator.free(decision_payload);
        _ = try journal.append(nowNs(self.io), "decision.preflight", decision_payload);
        if (mutating) _ = try journal.appendPreAction(nowNs(self.io), @tagName(assessment.action), redacted_prompt);

        const guarded_prompt = try buildCodexPrompt(self.allocator, prompt, assessment.action);
        defer self.allocator.free(guarded_prompt);

        var backend = try self.executeBackend(&journal, "codex.event", guarded_prompt, prompt, resume_thread_id, if (mutating) .workspace_write else .read_only);
        defer backend.deinit(self.allocator);
        if (!backend.succeeded) return .{ .succeeded = false, .thread_id = if (backend.thread_id) |id| try self.allocator.dupe(u8, id) else null };

        if (mutating) {
            const postflight_ok = try self.verifyPostflight(&journal, redacted_prompt, backend.transcript);
            if (!postflight_ok and backend.thread_id != null) {
                const repair_prompt = "Re-check the original goal against the current workspace. Repair only goal-alignment or verification-evidence gaps, do not expand scope, and run the most relevant existing tests. This is the single permitted repair turn.";
                _ = try journal.appendPreAction(nowNs(self.io), "repair.turn", repair_prompt);
                var repair = try self.executeBackend(&journal, "codex.repair_event", repair_prompt, repair_prompt, backend.thread_id, .workspace_write);
                defer repair.deinit(self.allocator);
                if (!repair.succeeded) return .{ .succeeded = false, .thread_id = if (repair.thread_id) |id| try self.allocator.dupe(u8, id) else null };
                if (!try self.verifyPostflight(&journal, redacted_prompt, repair.transcript)) return error.PostflightFailed;
                return .{ .succeeded = true, .thread_id = if (repair.thread_id) |id| try self.allocator.dupe(u8, id) else null };
            }
            if (!postflight_ok) return error.PostflightFailed;
        } else if (backend.thread_id) |thread_id| {
            const binding = try jsonOwned(self.allocator, .{
                .thread_id = thread_id,
                .workspace = self.workspace,
                .read_only = true,
            });
            defer self.allocator.free(binding);
            _ = try journal.append(nowNs(self.io), "thread.binding", binding);
        }
        return .{ .succeeded = true, .thread_id = if (backend.thread_id) |id| try self.allocator.dupe(u8, id) else null };
    }

    fn verifyPostflight(self: *Runtime, journal: *audit.Journal, prompt: []const u8, transcript: []const u8) !bool {
        const safe_transcript = try redact.redact(self.allocator, transcript);
        defer self.allocator.free(safe_transcript);
        const request = try preflight.buildPostflight(self.allocator, prompt, safe_transcript, null);
        defer self.allocator.free(request);
        const response = self.invokeJev(request) catch |err| {
            _ = try journal.append(nowNs(self.io), "decision.postflight_unavailable", "Jev verification unavailable; no automatic repair attempted.");
            return err;
        };
        defer self.allocator.free(response);
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const parsed = try preflight.parsePostflightLeaky(arena.allocator(), response);
        const payload = try jsonOwned(self.allocator, .{
            .goal_alignment = parsed.goal_alignment,
            .goal_confidence = parsed.goal_alignment_confidence,
            .evidence_quality = parsed.evidence_quality,
            .evidence_confidence = parsed.evidence_quality_confidence,
            .jev_model = parsed.resolved_model,
        });
        defer self.allocator.free(payload);
        _ = try journal.append(nowNs(self.io), "decision.postflight", payload);
        return parsed.passes();
    }

    fn executeBackend(
        self: *Runtime,
        journal: *audit.Journal,
        audit_action: []const u8,
        prompt: []const u8,
        output_prompt: []const u8,
        resume_thread_id: ?[]const u8,
        sandbox: codex_exec.Sandbox,
    ) !BackendOutcome {
        var stream: StreamContext = .{
            .allocator = self.allocator,
            .runtime = self,
            .journal = journal,
            .audit_action = audit_action,
            .prompt = prompt,
            .output_prompt = output_prompt,
        };
        errdefer stream.transcript.deinit(self.allocator);
        const sink: process_runner.EventSink = .{ .context = &stream, .on_event = StreamContext.receive };
        var state: codex_exec.ActivityState = .{};

        if (self.config.backend == .app_server) {
            const app_result = app_server.runTurn(self.allocator, self.io, .{
                .codex_path = self.binaries.codex,
                .cwd = self.workspace,
                .environ_map = self.environ,
                .prompt = prompt,
                .resume_thread_id = resume_thread_id,
                .model = self.config.model,
                .sandbox = sandbox,
                .approvals = .{ .decide = ApprovalContext.decide },
            }, &state, sink) catch |err| {
                if (!state.mayFallback()) return err;
                if (self.json) {
                    try self.emitter.emit(.warning, .{ .code = "app_server_pre_turn_fallback", .detail = @errorName(err) });
                } else {
                    try self.stderr.print("app-server failed before the turn; falling back to exec ({s}).\n", .{@errorName(err)});
                }
                return self.executeExec(prompt, resume_thread_id, sandbox, &state, &stream, sink);
            };
            var result = app_result;
            defer result.deinit(self.allocator);
            return .{
                .succeeded = result.succeeded(),
                .thread_id = try self.allocator.dupe(u8, result.thread_id),
                .transcript = try stream.transcript.toOwnedSlice(self.allocator),
            };
        }
        return self.executeExec(prompt, resume_thread_id, sandbox, &state, &stream, sink);
    }

    fn executeExec(self: *Runtime, prompt: []const u8, resume_thread_id: ?[]const u8, sandbox: codex_exec.Sandbox, state: *codex_exec.ActivityState, stream: *StreamContext, sink: process_runner.EventSink) !BackendOutcome {
        var result = try codex_exec.execute(self.allocator, self.io, .{
            .codex_path = self.binaries.codex,
            .cwd = .{ .path = self.workspace },
            .environ_map = self.environ,
            .prompt = prompt,
            .resume_thread_id = resume_thread_id,
            .model = self.config.model,
            .sandbox = sandbox,
        }, state, sink);
        defer result.deinit(self.allocator);
        if (!result.succeeded() and result.process.stderr.bytes.len != 0) {
            const safe = try sanitizeTextForOutput(self.allocator, result.process.stderr.bytes, stream.prompt, stream.output_prompt);
            defer self.allocator.free(safe);
            try self.stderr.print("codex failed; redacted diagnostics: {s}\n", .{safe});
        }
        return .{
            .succeeded = result.succeeded(),
            .thread_id = if (result.thread_id) |id| try self.allocator.dupe(u8, id) else null,
            .transcript = try stream.transcript.toOwnedSlice(self.allocator),
        };
    }

    fn invokeJev(self: *Runtime, request: []const u8) ![]u8 {
        var capture: JsonCapture = .{ .allocator = self.allocator };
        errdefer capture.deinit();
        var environment = try jevEnvironment(self.allocator, self.environ);
        defer wipeEnvironment(&environment);
        var result = try process_runner.run(self.allocator, self.io, .{
            .argv = &.{self.binaries.jev},
            .environ_map = &environment,
            .environment_policy = .exact,
            .stdin_data = request,
            .limits = .{
                .max_input_bytes = 1024 * 1024,
                .max_line_bytes = 4 * 1024 * 1024,
                .max_stdout_bytes = 4 * 1024 * 1024,
                .max_stderr_bytes = 64 * 1024,
                .max_stderr_capture_bytes = 4096,
                .max_events = 1,
                .timeout_ms = jev_process_watchdog_ms,
            },
            .sink = .{ .context = &capture, .on_event = JsonCapture.receive },
        });
        defer result.deinit(self.allocator);
        if (!result.succeeded()) return jevTermError(result.term);
        return capture.take() orelse error.EmptyResponse;
    }
};

const TurnOutcome = struct {
    succeeded: bool,
    thread_id: ?[]u8,

    fn deinit(self: *TurnOutcome, allocator: std.mem.Allocator) void {
        if (self.thread_id) |id| allocator.free(id);
        self.* = undefined;
    }
};

const BackendOutcome = struct {
    succeeded: bool,
    thread_id: ?[]u8,
    transcript: []u8,

    fn deinit(self: *BackendOutcome, allocator: std.mem.Allocator) void {
        if (self.thread_id) |id| allocator.free(id);
        allocator.free(self.transcript);
        self.* = undefined;
    }
};

const StreamContext = struct {
    allocator: std.mem.Allocator,
    runtime: *Runtime,
    journal: *audit.Journal,
    audit_action: []const u8,
    prompt: []const u8,
    output_prompt: []const u8,
    transcript: std.ArrayList(u8) = .empty,

    fn receive(raw_context: ?*anyopaque, event: process_runner.Event) !void {
        const self: *StreamContext = @ptrCast(@alignCast(raw_context.?));
        _ = try self.journal.append(nowNs(self.runtime.io), self.audit_action, event.raw);

        const safe = try sanitizeJsonForOutput(self.allocator, event.value.*, self.prompt, self.output_prompt);
        defer self.allocator.free(safe);
        try appendRecentEvidence(self.allocator, &self.transcript, safe);

        var parsed = try process_runner.parseStrict(self.allocator, safe);
        defer parsed.deinit();
        if (self.runtime.json) {
            try self.runtime.emitter.emit(.backend_event, parsed.value);
        } else {
            try renderHumanEvent(self.runtime.stdout, parsed.value);
        }
    }
};

const ApprovalContext = struct {
    fn decide(_: ?*anyopaque, _: app_server.ApprovalRequest) !app_server.ApprovalDecision {
        // All escalation requests fail closed. Commands and file changes that
        // fit the selected sandbox do not need this callback.
        return .decline;
    }
};

const JsonCapture = struct {
    allocator: std.mem.Allocator,
    body: ?[]u8 = null,

    fn receive(raw_context: ?*anyopaque, event: process_runner.Event) !void {
        const self: *JsonCapture = @ptrCast(@alignCast(raw_context.?));
        if (self.body != null) return error.MultipleResponses;
        self.body = try self.allocator.dupe(u8, event.raw);
    }

    fn take(self: *JsonCapture) ?[]u8 {
        const result = self.body;
        self.body = null;
        return result;
    }

    fn deinit(self: *JsonCapture) void {
        if (self.body) |body| self.allocator.free(body);
        self.* = undefined;
    }
};

const BinaryPaths = struct {
    codex: []u8,
    jev: []u8,

    fn deinit(self: BinaryPaths, allocator: std.mem.Allocator) void {
        allocator.free(self.codex);
        allocator.free(self.jev);
    }

    fn resolve(allocator: std.mem.Allocator, io: std.Io, codex_setting: []const u8, jev_setting: []const u8) !BinaryPaths {
        const exe = try std.process.executablePathAlloc(io, allocator);
        defer allocator.free(exe);
        const bin_dir = std.fs.path.dirname(exe) orelse return error.InvalidExecutable;
        const executable_suffix = if (builtin.os.tag == .windows) ".exe" else "";

        const codex = if (!std.mem.eql(u8, codex_setting, "codex"))
            try allocator.dupe(u8, codex_setting)
        else blk: {
            const name = try std.fmt.allocPrint(allocator, "codex{s}", .{executable_suffix});
            defer allocator.free(name);
            const bundled = try std.fs.path.join(allocator, &.{ bin_dir, "..", "vendor", "codex", "bin", name });
            if (std.Io.Dir.accessAbsolute(io, bundled, .{})) |_| break :blk bundled else |_| {
                allocator.free(bundled);
                break :blk try allocator.dupe(u8, "codex");
            }
        };
        errdefer allocator.free(codex);

        const jev = if (!std.mem.eql(u8, jev_setting, "jev-decide"))
            try allocator.dupe(u8, jev_setting)
        else blk: {
            const name = try std.fmt.allocPrint(allocator, "jev-decide{s}", .{executable_suffix});
            defer allocator.free(name);
            const sibling = try std.fs.path.join(allocator, &.{ bin_dir, name });
            if (std.Io.Dir.accessAbsolute(io, sibling, .{})) |_| break :blk sibling else |_| {
                allocator.free(sibling);
                break :blk try allocator.dupe(u8, "jev-decide");
            }
        };
        return .{ .codex = codex, .jev = jev };
    }
};

fn loadEffectiveConfig(allocator: std.mem.Allocator, io: std.Io, environ: *const std.process.Environ.Map, workspace: []const u8, options: cli.Options) !config.Value {
    const user_layer = blk: {
        const home = environ.get("HOME") orelse break :blk config.Layer{};
        const path = try std.fs.path.join(allocator, &.{ home, ".config", "jevx", "config.json" });
        defer allocator.free(path);
        break :blk try readOptionalLayer(allocator, io, path);
    };
    const project_path = try std.fs.path.join(allocator, &.{ workspace, ".jevx.json" });
    defer allocator.free(project_path);
    const project_layer = try readOptionalLayer(allocator, io, project_path);
    const environment_layer = try config.environmentLayer(environ);
    return config.resolve(user_layer, project_layer, environment_layer, config.commandLineLayer(options));
}

fn readOptionalLayer(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !config.Layer {
    var file = std.Io.Dir.openFileAbsolute(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => return .{},
        else => return err,
    };
    defer file.close(io);
    var buffer: [4096]u8 = undefined;
    var reader = file.reader(io, &buffer);
    const bytes = try reader.interface.allocRemaining(allocator, .limited(64 * 1024));
    return config.parseLayerLeaky(allocator, bytes);
}

fn canonicalWorkspace(allocator: std.mem.Allocator, io: std.Io, environ: *const std.process.Environ.Map, requested: ?[]const u8) ![]u8 {
    const owned_canonical = if (requested) |path| blk: {
        var dir = try std.Io.Dir.cwd().openDir(io, path, .{});
        defer dir.close(io);
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const length = try dir.realPath(io, &buffer);
        break :blk try allocator.dupe(u8, buffer[0..length]);
    } else blk: {
        const cwd = try std.process.currentPathAlloc(io, allocator);
        defer allocator.free(cwd);
        break :blk try allocator.dupe(u8, cwd);
    };
    errdefer allocator.free(owned_canonical);
    const canonical: []const u8 = owned_canonical;
    if (workspaceTooBroad(canonical, environ)) return error.WorkspaceTooBroad;
    return owned_canonical;
}

fn workspaceTooBroad(path: []const u8, environ: *const std.process.Environ.Map) bool {
    if (isFilesystemRoot(path)) return true;
    const home_names = [_][]const u8{ "HOME", "USERPROFILE" };
    for (home_names) |name| {
        if (environ.get(name)) |home| if (pathGuardEqual(path, home)) return true;
    }
    return false;
}

fn isFilesystemRoot(path: []const u8) bool {
    if (path.len == 0) return true;
    var only_separators = true;
    for (path) |byte| if (byte != '/' and byte != '\\') {
        only_separators = false;
        break;
    };
    if (only_separators) return true;
    if (path.len >= 3 and std.ascii.isAlphabetic(path[0]) and path[1] == ':') {
        for (path[2..]) |byte| if (byte != '/' and byte != '\\') return false;
        return true;
    }
    if (path.len >= 2 and isPathSeparator(path[0]) and isPathSeparator(path[1])) {
        var components: usize = 0;
        var inside = false;
        for (path[2..]) |byte| {
            if (isPathSeparator(byte)) {
                inside = false;
            } else if (!inside) {
                components += 1;
                inside = true;
            }
        }
        return components <= 2;
    }
    return false;
}

fn pathGuardEqual(a_raw: []const u8, b_raw: []const u8) bool {
    var a = a_raw;
    var b = b_raw;
    while (a.len > 1 and isPathSeparator(a[a.len - 1])) a = a[0 .. a.len - 1];
    while (b.len > 1 and isPathSeparator(b[b.len - 1])) b = b[0 .. b.len - 1];
    if (a.len != b.len) return false;
    for (a, b) |left, right| {
        if (isPathSeparator(left) and isPathSeparator(right)) continue;
        if (std.ascii.toLower(left) != std.ascii.toLower(right)) return false;
    }
    return true;
}

fn isPathSeparator(byte: u8) bool {
    return byte == '/' or byte == '\\';
}

fn readStdin(allocator: std.mem.Allocator, io: std.Io, limit: usize) ![]u8 {
    var buffer: [16 * 1024]u8 = undefined;
    var reader = std.Io.File.stdin().readerStreaming(io, &buffer);
    return reader.interface.allocRemaining(allocator, .limited(limit));
}

fn readFileBounded(allocator: std.mem.Allocator, io: std.Io, path: []const u8, limit: usize) ![]u8 {
    var file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    var buffer: [16 * 1024]u8 = undefined;
    var reader = file.reader(io, &buffer);
    return reader.interface.allocRemaining(allocator, .limited(limit));
}

fn safeCodexEnvironment(allocator: std.mem.Allocator, source: *const std.process.Environ.Map) !std.process.Environ.Map {
    var result = std.process.Environ.Map.init(allocator);
    errdefer result.deinit();
    const names = [_][]const u8{
        "PATH",    "HOME",       "USER",            "LOGNAME",        "SHELL",          "TMPDIR",       "TMP",     "TEMP",        "TERM",       "COLORTERM",
        "LANG",    "CODEX_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME", "LOCALAPPDATA", "APPDATA", "USERPROFILE", "SystemRoot", "ComSpec",
        "PATHEXT",
    };
    for (names) |name| if (source.get(name)) |value| try result.put(name, value);
    var iterator = source.iterator();
    while (iterator.next()) |entry| {
        if (std.mem.startsWith(u8, entry.key_ptr.*, "LC_")) try result.put(entry.key_ptr.*, entry.value_ptr.*);
    }
    return result;
}

fn jevEnvironment(allocator: std.mem.Allocator, source: *const std.process.Environ.Map) !std.process.Environ.Map {
    var result = try process_runner.sanitizeEnvironment(allocator, source);
    errdefer result.deinit();
    if (source.get("OPENROUTER_API_KEY")) |key| try result.put("OPENROUTER_API_KEY", key);
    return result;
}

fn wipeEnvironment(environment: *std.process.Environ.Map) void {
    var iterator = environment.iterator();
    while (iterator.next()) |entry| std.crypto.secureZero(u8, @constCast(entry.value_ptr.*));
    environment.deinit();
}

fn jevTermError(term: std.process.Child.Term) anyerror {
    return switch (term) {
        .exited => |code| switch (code) {
            exit_codes.usage => error.InvalidDecisionRequest,
            exit_codes.dependency => error.MissingDependency,
            exit_codes.transient => error.TransportFailed,
            exit_codes.protocol => error.DecisionProviderRejected,
            exit_codes.authentication => error.AuthenticationFailed,
            exit_codes.policy => error.PolicyDenied,
            else => error.DecisionProcessFailed,
        },
        .signal, .stopped, .unknown => error.TransportFailed,
    };
}

fn buildCodexPrompt(allocator: std.mem.Allocator, prompt: []const u8, action: policy.ActionKind) ![]u8 {
    return std.fmt.allocPrint(allocator,
        \\jevx immutable execution constraints:
        \\- Operate only in the selected sandbox and action class `{s}`.
        \\- Never read, reveal, copy, or search for credentials, tokens, keychains, authentication files, or unrelated private data.
        \\- Never access the network, push, release, deploy, message, purchase, change accounts, elevate privileges, weaken policy, or bypass the sandbox.
        \\- If a required step needs an approval or exceeds these constraints, stop and explain the blocked step.
        \\User request follows between literal delimiters.
        \\<jevx-user-request>
        \\{s}
        \\</jevx-user-request>
    , .{ @tagName(action), prompt });
}

fn resumeThreadAllowed(
    allocator: std.mem.Allocator,
    journal: *audit.Journal,
    thread_id: []const u8,
    workspace: []const u8,
) !bool {
    var records = try journal.show(allocator);
    defer records.deinit();
    var index = records.items.len;
    while (index > 0) {
        index -= 1;
        const record = records.items[index];
        if (!std.mem.eql(u8, record.action, "thread.binding")) continue;
        var parsed = process_runner.parseStrict(allocator, record.payload) catch continue;
        defer parsed.deinit();
        if (parsed.value != .object) continue;
        const bound_id = jsonString(parsed.value.object.get("thread_id")) orelse continue;
        if (!std.mem.eql(u8, bound_id, thread_id)) continue;
        const bound_workspace = jsonString(parsed.value.object.get("workspace")) orelse return false;
        const read_only_value = parsed.value.object.get("read_only") orelse return false;
        return read_only_value == .bool and read_only_value.bool and std.mem.eql(u8, bound_workspace, workspace);
    }
    return false;
}

fn appendRecentEvidence(allocator: std.mem.Allocator, transcript: *std.ArrayList(u8), event: []const u8) !void {
    const event_len = @min(event.len, max_evidence_bytes - 1);
    const event_tail = event[event.len - event_len ..];
    const needed = event_tail.len + 1;
    if (transcript.items.len + needed > max_evidence_bytes) {
        const drop = transcript.items.len + needed - max_evidence_bytes;
        const remaining = transcript.items.len - @min(drop, transcript.items.len);
        if (remaining != 0) {
            std.mem.copyForwards(u8, transcript.items[0..remaining], transcript.items[transcript.items.len - remaining ..]);
        }
        transcript.shrinkRetainingCapacity(remaining);
    }
    try transcript.appendSlice(allocator, event_tail);
    try transcript.append(allocator, '\n');
}

fn sanitizeTextForOutput(
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

fn sanitizeJsonForOutput(
    allocator: std.mem.Allocator,
    value: std.json.Value,
    full_prompt: []const u8,
    user_prompt: []const u8,
) ![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    try writeSanitizedJson(allocator, &output.writer, value, full_prompt, user_prompt);
    return output.toOwnedSlice();
}

fn writeSanitizedJson(
    allocator: std.mem.Allocator,
    writer: *std.Io.Writer,
    value: std.json.Value,
    full_prompt: []const u8,
    user_prompt: []const u8,
) !void {
    switch (value) {
        .string => |text_value| {
            const safe = try sanitizeTextForOutput(allocator, text_value, full_prompt, user_prompt);
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
                try writeSanitizedJson(allocator, writer, item, full_prompt, user_prompt);
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
                try writeSanitizedJson(allocator, writer, entry.value_ptr.*, full_prompt, user_prompt);
            }
            try writer.writeByte('}');
        },
        else => try std.json.Stringify.value(value, .{}, writer),
    }
}

fn jsonOwned(allocator: std.mem.Allocator, value: anytype) ![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    try std.json.Stringify.value(value, .{}, &output.writer);
    return output.toOwnedSlice();
}

fn commandProbe(allocator: std.mem.Allocator, io: std.Io, argv: []const []const u8, environ: *const std.process.Environ.Map, expected: []const u8) !bool {
    const result = try std.process.run(allocator, io, .{
        .argv = argv,
        .environ_map = environ,
        .stdout_limit = .limited(128 * 1024),
        .stderr_limit = .limited(128 * 1024),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(20), .clock = .awake } },
    });
    defer {
        allocator.free(result.stdout);
        allocator.free(result.stderr);
    }
    const success = switch (result.term) {
        .exited => |status| status == 0,
        else => false,
    };
    return success and (std.mem.indexOf(u8, result.stdout, expected) != null or std.mem.indexOf(u8, result.stderr, expected) != null);
}

fn renderHumanEvent(writer: *std.Io.Writer, value: std.json.Value) !void {
    if (value != .object) return;
    const event_type = jsonString(value.object.get("type")) orelse jsonString(value.object.get("method")) orelse return;
    if (std.mem.eql(u8, event_type, "item.completed") or std.mem.eql(u8, event_type, "item.started")) {
        const item_value = value.object.get("item") orelse return;
        if (item_value != .object) return;
        const item_type = jsonString(item_value.object.get("type")) orelse return;
        if (std.mem.eql(u8, item_type, "agent_message")) {
            if (jsonString(item_value.object.get("text"))) |text| try writer.print("{s}\n", .{text});
        } else if (std.mem.eql(u8, item_type, "command_execution") and std.mem.eql(u8, event_type, "item.started")) {
            if (jsonString(item_value.object.get("command"))) |command| try writer.print("$ {s}\n", .{command});
        } else if (std.mem.eql(u8, item_type, "command_execution") and std.mem.eql(u8, event_type, "item.completed")) {
            if (jsonString(item_value.object.get("aggregated_output"))) |output| if (output.len != 0) try writer.print("{s}", .{output});
        }
    } else if (std.mem.startsWith(u8, event_type, "turn/") or std.mem.startsWith(u8, event_type, "item/")) {
        try writer.print("[{s}]\n", .{event_type});
    }
    try writer.flush();
}

fn jsonString(value: ?std.json.Value) ?[]const u8 {
    const actual = value orelse return null;
    return if (actual == .string) actual.string else null;
}

fn askConfirmation(io: std.Io, writer: *std.Io.Writer, message: []const u8) !bool {
    try writer.writeAll(message);
    try writer.flush();
    var buffer: [128]u8 = undefined;
    var reader = std.Io.File.stdin().readerStreaming(io, &buffer);
    const answer = (try reader.interface.takeDelimiter('\n')) orelse return false;
    const trimmed = std.mem.trim(u8, answer, " \t\r\n");
    return std.ascii.eqlIgnoreCase(trimmed, "y") or std.ascii.eqlIgnoreCase(trimmed, "yes");
}

fn nowNs(io: std.Io) i64 {
    return @intCast(std.Io.Clock.real.now(io).nanoseconds);
}

fn mark(ok: bool) []const u8 {
    return if (ok) "ok" else "failed";
}

fn printHelp(writer: *std.Io.Writer) !void {
    try writer.writeAll(
        \\jevx - unofficial Jev-powered Zig terminal agent
        \\
        \\Usage:
        \\  jevx                         Start the streaming REPL
        \\  jevx run                     Run one prompt from stdin
        \\  jevx resume THREAD_ID        Resume a Codex thread with a prompt from stdin
        \\  jevx decide                  Send one typed Jev request from stdin
        \\  jevx doctor                  Check dependencies, auth, and audit integrity
        \\  jevx policy explain          Show effective policy and immutable guards
        \\  jevx audit show|verify|export|purge
        \\  jevx setup                   Authenticate and initialize the audit key
        \\  jevx version
        \\
        \\Options:
        \\  --backend exec|app-server
        \\  --policy aggressive|balanced|conservative
        \\  --model MODEL                Select the Codex model
        \\  --json                       Emit versioned JSONL
        \\  -C DIRECTORY                 Select and canonicalize the workspace
        \\  --codex-bin PATH             Explicit Codex executable
        \\  --jev-bin PATH               Explicit jev-decide executable
        \\  --prompt-file PATH            Read a prompt from a file instead of stdin
        \\
        \\Prompts and credentials are never placed in child-process arguments.
        \\
    );
}

test "safe Codex environment omits credential-shaped variables" {
    var source = std.process.Environ.Map.init(std.testing.allocator);
    defer source.deinit();
    try source.put("PATH", "/bin");
    try source.put("HOME", "/home/test");
    try source.put("OPENROUTER_API_KEY", "must-not-leak");
    try source.put("AWS_SECRET_ACCESS_KEY", "must-not-leak");
    var safe = try safeCodexEnvironment(std.testing.allocator, &source);
    defer safe.deinit();
    try std.testing.expectEqualStrings("/bin", safe.get("PATH").?);
    try std.testing.expect(safe.get("OPENROUTER_API_KEY") == null);
    try std.testing.expect(safe.get("AWS_SECRET_ACCESS_KEY") == null);
}

test "stable error mapping covers every public exit class" {
    try std.testing.expectEqual(exit_codes.dependency, classifyError(error.MissingDependency));
    try std.testing.expectEqual(exit_codes.authentication, classifyError(error.AuthenticationFailed));
    try std.testing.expectEqual(exit_codes.policy, classifyError(error.PolicyDenied));
    try std.testing.expectEqual(exit_codes.transient, classifyError(error.CircuitOpen));
    try std.testing.expectEqual(exit_codes.protocol, classifyError(error.InvalidDecisionRequest));
    try std.testing.expectEqual(exit_codes.audit, classifyError(error.CorruptJournal));
    try std.testing.expectEqual(exit_codes.agent, classifyError(error.UnexpectedAgentFailure));
}

test "workspace guard rejects POSIX Windows and home roots" {
    var environment = std.process.Environ.Map.init(std.testing.allocator);
    defer environment.deinit();
    try environment.put("HOME", "/Users/example/");
    try environment.put("USERPROFILE", "C:\\Users\\Example");
    try std.testing.expect(workspaceTooBroad("/", &environment));
    try std.testing.expect(workspaceTooBroad("C:\\", &environment));
    try std.testing.expect(workspaceTooBroad("\\\\server\\share", &environment));
    try std.testing.expect(workspaceTooBroad("/Users/example", &environment));
    try std.testing.expect(workspaceTooBroad("c:/users/example/", &environment));
    try std.testing.expect(!workspaceTooBroad("/Users/example/project", &environment));
    try std.testing.expect(!workspaceTooBroad("C:\\Users\\Example\\project", &environment));
}

test "stream output redacts exact prompts and credential material" {
    const original = "inspect this private prompt";
    const guarded = try buildCodexPrompt(std.testing.allocator, original, .read);
    defer std.testing.allocator.free(guarded);
    const raw = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"type\":\"item.completed\",\"item\":{{\"type\":\"agent_message\",\"text\":\"{s} sk-secret-12345678901234567890\"}},\"input\":{f}}}",
        .{ original, std.json.fmt(guarded, .{}) },
    );
    defer std.testing.allocator.free(raw);
    var parsed = try process_runner.parseStrict(std.testing.allocator, raw);
    defer parsed.deinit();
    const safe = try sanitizeJsonForOutput(std.testing.allocator, parsed.value, guarded, original);
    defer std.testing.allocator.free(safe);
    try std.testing.expect(std.mem.indexOf(u8, safe, original) == null);
    try std.testing.expect(std.mem.indexOf(u8, safe, "sk-secret") == null);
    try std.testing.expect(std.mem.indexOf(u8, safe, "[PROMPT REDACTED]") != null);
}

test "recent evidence remains bounded and keeps the tail" {
    var evidence: std.ArrayList(u8) = .empty;
    defer evidence.deinit(std.testing.allocator);
    const large = try std.testing.allocator.alloc(u8, max_evidence_bytes + 100);
    defer std.testing.allocator.free(large);
    @memset(large, 'a');
    @memcpy(large[large.len - 4 ..], "TAIL");
    try appendRecentEvidence(std.testing.allocator, &evidence, large);
    try std.testing.expectEqual(max_evidence_bytes, evidence.items.len);
    try std.testing.expect(std.mem.endsWith(u8, evidence.items, "TAIL\n"));
}

test "app-server escalation approvals always fail closed" {
    const id: std.json.Value = .{ .integer = 1 };
    const request: app_server.ApprovalRequest = .{
        .kind = .command,
        .method = "item/commandExecution/requestApproval",
        .id = &id,
        .params = null,
    };
    try std.testing.expectEqual(app_server.ApprovalDecision.decline, try ApprovalContext.decide(null, request));
}

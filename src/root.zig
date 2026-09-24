//! Core library for the unofficial jevx terminal agent.

pub const version = "1.0.0";
pub const schema_version = "jevx.event.v1";

pub const app = @import("app.zig");
pub const app_server = @import("app_server.zig");
pub const audit = @import("audit.zig");
pub const cli = @import("cli.zig");
pub const codex_exec = @import("codex_exec.zig");
pub const config = @import("config.zig");
pub const events = @import("events.zig");
pub const exit_codes = @import("exit_codes.zig");
pub const decision = @import("decision.zig");
pub const jev_client = @import("jev_client.zig");
pub const policy = @import("policy.zig");
pub const preflight = @import("preflight.zig");
pub const process_runner = @import("process_runner.zig");
pub const redact = @import("redact.zig");
pub const secret_store = @import("secret_store.zig");
pub const state_paths = @import("state_paths.zig");
pub const web_bridge = @import("web_bridge.zig");

test {
    _ = app;
    _ = app_server;
    _ = audit;
    _ = cli;
    _ = config;
    _ = events;
    _ = exit_codes;
    _ = decision;
    _ = jev_client;
    _ = policy;
    _ = preflight;
    _ = process_runner;
    _ = redact;
    _ = secret_store;
    _ = state_paths;
    _ = web_bridge;
}

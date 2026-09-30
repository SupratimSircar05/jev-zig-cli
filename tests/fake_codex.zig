//! Native-run integration fixture for the Codex JSONL boundary.

const std = @import("std");

const guarded_prompt = "integration guarded prompt: exact private prompt";

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    for (args[1..]) |arg| {
        if (std.mem.indexOf(u8, arg, guarded_prompt) != null or
            std.mem.indexOf(u8, arg, "exact private prompt") != null)
        {
            return error.PromptLeakedIntoArgv;
        }
    }

    var stdin_buffer: [4096]u8 = undefined;
    var stdin_reader = std.Io.File.stdin().readerStreaming(init.io, &stdin_buffer);
    const input = try stdin_reader.interface.allocRemaining(init.gpa, .limited(4096));
    defer {
        std.crypto.secureZero(u8, input);
        init.gpa.free(input);
    }
    if (!std.mem.eql(u8, input, guarded_prompt)) return error.UnexpectedPrompt;

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_file = std.Io.File.stdout().writer(init.io, &stdout_buffer);
    const stdout = &stdout_file.interface;
    try stdout.writeAll(
        \\{"type":"thread.started","thread_id":"integration-thread","authorization":"opaque-auth-value","future_field":"kept"}
        \\{"type":"turn.started","nested":{"api_key":"opaque-api-value"}}
        \\{"type":"item.completed","item":{"type":"agent_message","text":"integration guarded prompt: exact private prompt and sk-secret-12345678901234567890","vendor_secret":{"raw":"opaque-object-value"}},"extra":[{"session_token":"opaque-session-value"}]}
        \\
    );
    try stdout.flush();
}

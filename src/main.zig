const std = @import("std");
const jevx = @import("jevx");

pub fn main(init: std.process.Init) !void {
    var stdout_buffer: [16 * 1024]u8 = undefined;
    var stdout_file = std.Io.File.stdout().writer(init.io, &stdout_buffer);
    const stdout = &stdout_file.interface;
    var stderr_buffer: [8 * 1024]u8 = undefined;
    var stderr_file = std.Io.File.stderr().writer(init.io, &stderr_buffer);
    const stderr = &stderr_file.interface;

    const code = jevx.app.run(init, stdout, stderr) catch |err| blk: {
        stderr.print("jevx: {s}\n", .{@errorName(err)}) catch {};
        break :blk jevx.app.classifyError(err);
    };
    stdout.flush() catch {};
    stderr.flush() catch {};
    if (code != 0) std.process.exit(code);
}

test {
    _ = jevx;
}

const std = @import("std");

pub fn main() !void {
    return;
}

test "all" {
    _ = @import("buffer.zig");
    _ = @import("packet.zig");
    _ = @import("frame.zig");
    _ = @import("tls.zig");
    _ = @import("util.zig");

    std.testing.refAllDecls(@This());
}

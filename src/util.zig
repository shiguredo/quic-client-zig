const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;

pub fn getBigEndianInt(comptime T: type, int: T) T {
    const ret: T = switch (std.Target.Cpu.Arch.endian(builtin.cpu.arch)) {
        .Big => int,
        .Little => @byteSwap(T, int),
    };
    return ret;
}

test "getBigEndian" {
    try testing.expect(getBigEndianInt(u32, 0x01020304) == @as(u32, 0x04030201));
}
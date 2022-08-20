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

pub const WriteError = error {
    BufferShortError,
};

/// write value in BIG ENDIAN and returns written byte count
pub fn writeIntReturnSize(comptime T: type, dst: []u8, value: T) WriteError!usize {
    const write_size = @as(usize, @bitSizeOf(T) / 8);
    if (dst.len < write_size) return WriteError.BufferShortError;

    std.mem.writeInt(T, dst[0..write_size], value, .Big);
    return write_size;
}

/// copy buffer with offset and returns written byte count
pub fn copyReturnSize(dst: []u8, source: []const u8) WriteError!usize {
    if (dst.len < source.len) return WriteError.BufferShortError;

    const len = source.len;
    std.mem.copy(u8, dst[0..len], source);
    return len;
}

pub const VariableLengthInt = struct {
    len: usize,
    value: u64,

    const Self = @This();

    const parseError = error{
        ShortLenError,
        InvalidLenError,
    };

    /// convert self to integer type T as variable length format
    pub fn toInt(self: *const Self, comptime T: type) parseError!T {
        const len_bits: T = switch (T) {
            u8 => 0x0000000000000000,
            u16 => 0x0000000000004000,
            u32 => 0x0000000080000000,
            u64 => 0xf000000000000000,
            else => @compileError("T must be u8, u16, u32 or u64"),
        };

        const mask: T = switch (T) {
            u8 => 0x000000000000003f,
            u16 => 0x0000000000003fff,
            u32 => 0x000000003fffffff,
            u64 => 0x3fffffffffffffff,
            else => @compileError("T must be u8, u16, u32 or u64"),
        };

        const masked: T = @intCast(T, self.value & mask);
        return masked | len_bits;
    }

    /// create variableLenInt from u8 array
    /// array length must be longer than passed len, 
    /// which must equal to 1, 2, 4 or 8 
    pub fn fromU8Array(len: usize, array: []const u8) parseError!Self {
        if (array.len < len) {
            return parseError.ShortLenError;
        }

        var copy_arr: [8]u8 = undefined;

        std.mem.copy(u8, copy_arr[0..len], array[0..len]);
        copy_arr[0] &= 0x3f;

        const value: u64 = switch (len) {
            1 => std.mem.readInt(u8, copy_arr[0..1], .Big),
            2 => std.mem.readInt(u16, copy_arr[0..2], .Big),
            4 => std.mem.readInt(u32, copy_arr[0..4], .Big),
            8 => std.mem.readInt(u64, copy_arr[0..8], .Big),
            else => return parseError.InvalidLenError,
        };

        return Self{
            .value = value,
            .len = len,
        };
    }

    /// calculate length from the first byte of variable length interger
    pub fn calcLenBits(byte: u8) usize {
        const mask: u8 = 0xc0;
        const masked: u8 = byte & mask;
        return switch (masked) {
            0x00 => 1,
            0x40 => 2,
            0x80 => 4,
            0xc0 => 8,
            else => unreachable,
        };
    }
};

test "convert u8 array to variable length int" {
    const array1: [4]u8 = .{ 0x81, 0x04, 0x48, 0xad };
    const len1 = VariableLengthInt.calcLenBits(array1[0]);
    const v_int1 = try VariableLengthInt.fromU8Array(len1, array1[0..len1]);
    try testing.expectEqual(@as(usize, 4), len1);
    try testing.expectEqual(@as(u64, 0x010448ad), v_int1.value);
}

test "convert variable length int to normal integer" {
    const v_int = VariableLengthInt{ .value = 0x36f8, .len = 2 };
    const converted = try v_int.toInt(u16);
    try testing.expectEqual(@as(u16, 0x36f8 | 0x4000), converted);
}

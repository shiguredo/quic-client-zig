const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;

pub const WriteError = error{
    BufferTooShort,
};

/// write value in BIG ENDIAN and returns written byte count
pub fn writeIntReturnSize(comptime T: type, dst: []u8, value: T) WriteError!usize {
    const write_size = @as(usize, @bitSizeOf(T) / 8);
    if (dst.len < write_size) return WriteError.BufferTooShort;

    std.mem.writeInt(T, dst[0..write_size], value, .Big);
    return write_size;
}

/// copy buffer with offset and returns written byte count
pub fn copyReturnSize(dst: []u8, source: []const u8) WriteError!usize {
    if (dst.len < source.len) return WriteError.BufferTooShort;

    const len = source.len;
    std.mem.copy(u8, dst[0..len], source);
    return len;
}

/// implementation for Variable-Length Interger
/// https://www.rfc-editor.org/rfc/rfc9000.html#name-variable-length-integer-enc
pub const VariableLengthInt = struct {
    len: usize,
    value: u64,

    const Self = @This();

    pub const Error = error{ VLIntLengthShort, VLIntInvalidLength, VLIntInvalidValue } || WriteError;

    /// encode to u8 array
    pub fn encode(self: *const Self, out: []u8) Error!usize {
        if (out.len < self.len) return Error.BufferTooShort;
        if (self.value >= (@as(u64, 1) << @intCast(u6, self.len * 8 - 2)))
            return Error.VLIntLengthShort; // check for having enough length to express the value

        const len_bits_mask: u8 = switch (self.len) {
            1 => 0x00,
            2 => 0x40,
            4 => 0x80,
            8 => 0xC0,
            else => return Error.VLIntInvalidLength,
        };

        const count = switch (self.len) {
            1 => writeIntReturnSize(u8, out[0..1], @intCast(u8, self.value)),
            2 => writeIntReturnSize(u16, out[0..2], @intCast(u16, self.value)),
            4 => writeIntReturnSize(u32, out[0..4], @intCast(u32, self.value)),
            8 => writeIntReturnSize(u64, out[0..8], @intCast(u64, self.value)),
            else => unreachable,
        };

        out[0] |= len_bits_mask;

        return count;
    }

    /// decode variable-length-interger-coded u8 array
    pub fn decode(array: []const u8) Error!Self {
        if (array.len == 0) return Error.BufferTooShort;
        const len_bits = array[0] & 0xC0;
        const length: usize = switch (len_bits) {
            0x00 => 1,
            0x40 => 2,
            0x80 => 4,
            0xC0 => 8,
            else => unreachable,
        };

        if (array.len < length) return Error.BufferTooShort;

        var copy: [8]u8 = undefined;
        std.mem.copy(u8, &copy, array[0..length]);
        copy[0] &= 0x3F; // remove length field

        const value = switch (length) {
            1 => @intCast(usize, std.mem.readIntBig(u8, copy[0..1])),
            2 => @intCast(usize, std.mem.readIntBig(u16, copy[0..2])),
            4 => @intCast(usize, std.mem.readIntBig(u32, copy[0..4])),
            8 => @intCast(usize, std.mem.readIntBig(u64, copy[0..8])),
            else => unreachable,
        };

        return Self{
            .len = length,
            .value = value,
        };
    }

    pub fn fromU64(value: u64) Error!Self {
        const ONE_BIT_MAX = (1 << 6) - 1;
        const TWO_BITS_MAX = (1 << 14) - 1;
        const FOUR_BITS_MAX = (1 << 30) - 1;
        const EIGHT_BITS_MAX = (1 << 62) - 1;

        const length: usize = switch (value) {
            0...ONE_BIT_MAX => 1,
            (ONE_BIT_MAX + 1)...TWO_BITS_MAX => 2,
            (TWO_BITS_MAX + 1)...FOUR_BITS_MAX => 4,
            (FOUR_BITS_MAX + 1)...EIGHT_BITS_MAX => 8,
            else => return Error.VLIntInvalidValue,
        };

        return Self{
            .value = value,
            .len = length,
        };
    }
};

test "decode u8 array to variable length int" {
    const array1: [4]u8 = .{ 0x81, 0x04, 0x48, 0xad };
    const v_int1 = try VariableLengthInt.decode(&array1);
    try testing.expectEqual(@as(usize, 4), v_int1.len);
    try testing.expectEqual(@as(u64, 0x010448ad), v_int1.value);
}

test "encode variable length int to u8 array" {
    const v_int = VariableLengthInt{ .value = 0x010448ad, .len = 4 };
    var encoded: [8]u8 = undefined;
    const encode_len = try v_int.encode(&encoded);
    try testing.expectEqual(@as(usize, 4), encode_len);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x81, 0x04, 0x48, 0xad }, encoded[0..v_int.len]);
}

test "convert to variable length int from u64" {
    const v_int = try VariableLengthInt.fromU64(0x010448ad);
    try testing.expectEqual(
        VariableLengthInt{ .value = 0x010448ad, .len = 4 },
        v_int,
    );
}

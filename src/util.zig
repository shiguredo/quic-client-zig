const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const testing = std.testing;

const buffer = @import("buffer.zig");
const Buffer = buffer.Buffer;
const BufferError = buffer.BufferError;

/// implementation for Variable-Length Interger
/// https://www.rfc-editor.org/rfc/rfc9000.html#name-variable-length-integer-enc
pub const VariableLengthInt = struct {
    len: usize,
    value: u64,

    const Self = @This();

    pub const Error = error{ VLIntLengthShort, VLIntInvalidLength, VLIntInvalidValue } || BufferError;

    /// encode to writer in Variable-length-integer format
    pub fn encode(self: *const Self, writer: anytype) Error!void {
        if (self.value >= (@as(u64, 1) << @intCast(u6, self.len * 8 - 2)))
            return Error.VLIntLengthShort; // check for having enough length to express the value

        const len_bits_mask: u8 = switch (self.len) {
            1 => 0x00,
            2 => 0x40,
            4 => 0x80,
            8 => 0xC0,
            else => return Error.VLIntInvalidLength,
        };

        var temp = [_]u8{0} ** 8;

        switch (self.len) {
            1 => mem.writeIntBig(u8, temp[0..1], @intCast(u8, self.value)),
            2 => mem.writeIntBig(u16, temp[0..2], @intCast(u16, self.value)),
            4 => mem.writeIntBig(u32, temp[0..4], @intCast(u32, self.value)),
            8 => mem.writeIntBig(u64, temp[0..8], @intCast(u64, self.value)),
            else => unreachable,
        }

        temp[0] |= len_bits_mask;

        _ = try writer.write(temp[0..self.len]);

        return;
    }

    /// decode variable-length-interger-coded array via reader
    pub fn decode(reader: anytype) !Self {
        var temp = [_]u8{0} ** 8;
        temp[0] = try reader.readByte();

        const len_bits = temp[0] & 0xC0;
        const length: usize = switch (len_bits) {
            0x00 => 1,
            0x40 => 2,
            0x80 => 4,
            0xC0 => 8,
            else => unreachable,
        };

        if (length > 1) {
            const count = try reader.read(temp[1..length]);
            if (count + 1 < length) return Error.NotEnoughUnreadLength;
        }

        temp[0] &= 0x3F; // remove length field

        const value = switch (length) {
            1 => @intCast(usize, std.mem.readIntBig(u8, temp[0..1])),
            2 => @intCast(usize, std.mem.readIntBig(u16, temp[0..2])),
            4 => @intCast(usize, std.mem.readIntBig(u32, temp[0..4])),
            8 => @intCast(usize, std.mem.readIntBig(u64, temp[0..8])),
            else => unreachable,
        };

        return Self{
            .len = length,
            .value = value,
        };
    }

    pub fn fromInt(value: anytype) Error!Self {
        const val_u64 = if (@TypeOf(value) == u64) value else @intCast(u64, value);
        return fromU64(val_u64);
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
    var buf = Buffer(32).init();
    _ = try buf.writer().write(&[4]u8{ 0x81, 0x04, 0x48, 0xad });
    const v_int1 = try VariableLengthInt.decode(buf.reader());
    try testing.expectEqual(@as(usize, 4), v_int1.len);
    try testing.expectEqual(@as(u64, 0x010448ad), v_int1.value);
}

test "encode variable length int to u8 array" {
    const v_int = VariableLengthInt{ .value = 0x010448ad, .len = 4 };
    var buf = Buffer(32).init();
    try v_int.encode(buf.writer());
    try testing.expectEqual(@as(usize, 4), buf.unreadLength());
    try testing.expectEqualSlices(u8, &[_]u8{ 0x81, 0x04, 0x48, 0xad }, buf.getUnreadSlice());
}

test "convert to variable length int from u64" {
    const v_int = try VariableLengthInt.fromU64(0x010448ad);
    try testing.expectEqual(
        VariableLengthInt{ .value = 0x010448ad, .len = 4 },
        v_int,
    );
}

const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const io = std.io;
const testing = std.testing;

const buffer = @import("buffer.zig");
const Buffer = buffer.Buffer;
const BufferError = buffer.BufferError;

/// implementation for Variable-Length Interger
/// https://www.rfc-editor.org/rfc/rfc9000.html#name-variable-length-integer-enc
pub const VarInt = struct {
    len: Length,
    value: u64,

    const Self = @This();

    pub const Length = enum(u2) {
        one = 0b00,
        two = 0b01,
        four = 0b10,
        eight = 0b11,

        pub fn mask(self: Length) u8 {
            return switch (self) {
                .one => 0x00,
                .two => 0x40,
                .four => 0x80,
                .eight => 0xC0,
            };
        }

        pub fn fromFirstByte(byte: u8) Length {
            const len_bits: u8 = byte & 0b11000000;
            return switch (len_bits) {
                0x00 => .one,
                0x40 => .two,
                0x80 => .four,
                0xC0 => .eight,
                else => unreachable,
            };
        }

        pub fn toUsize(self: Length) usize {
            return switch (self) {
                .one => 1,
                .two => 2,
                .four => 4,
                .eight => 8,
            };
        }
    };

    pub const Error = error{ VLIntLengthShort, VLIntInvalidLength, VLIntInvalidValue };

    /// encode to writer in Variable-length-integer format
    pub fn encode(self: *const Self, writer: anytype) @TypeOf(writer).Error!void {
        const len_bits_mask: u8 = self.len.mask();

        var temp = [_]u8{0} ** 8;

        switch (self.len) {
            .one => mem.writeIntBig(u8, temp[0..1], @intCast(u8, self.value)),
            .two => mem.writeIntBig(u16, temp[0..2], @intCast(u16, self.value)),
            .four => mem.writeIntBig(u32, temp[0..4], @intCast(u32, self.value)),
            .eight => mem.writeIntBig(u64, temp[0..8], @intCast(u64, self.value)),
        }

        temp[0] |= len_bits_mask;

        _ = try writer.write(temp[0..self.getLength()]);

        return;
    }

    /// decode variable-length-interger-coded array via reader
    pub fn decode(reader: anytype) !Self {
        var buf = [_]u8{0} ** 8;
        buf[0] = try reader.readByte();

        const length = Length.fromFirstByte(buf[0]);

        if (length != .one) {
            _ = try reader.readAll(buf[1..length.toUsize()]);
        }

        buf[0] &= 0x3F; // remove length field

        const value = switch (length) {
            .one => @intCast(u64, mem.readIntBig(u8, buf[0..1])),
            .two => @intCast(u64, mem.readIntBig(u16, buf[0..2])),
            .four => @intCast(u64, mem.readIntBig(u32, buf[0..4])),
            .eight => mem.readIntBig(u64, buf[0..8]),
        };

        return Self{
            .len = length,
            .value = value,
        };
    }

    pub fn fromInt(value: anytype) Self {
        const val_u64 = if (@TypeOf(value) == u64) value else @intCast(u64, value);
        return fromU64(val_u64);
    }

    fn fromU64(value: u64) Self {
        const ONE_BIT_MAX = (1 << 6) - 1;
        const TWO_BITS_MAX = (1 << 14) - 1;
        const FOUR_BITS_MAX = (1 << 30) - 1;
        const EIGHT_BITS_MAX = (1 << 62) - 1;

        const length: Length = switch (value) {
            0...ONE_BIT_MAX => .one,
            (ONE_BIT_MAX + 1)...TWO_BITS_MAX => .two,
            (TWO_BITS_MAX + 1)...FOUR_BITS_MAX => .four,
            (FOUR_BITS_MAX + 1)...EIGHT_BITS_MAX => .eight,
            else => unreachable,
        };

        return Self{
            .value = value,
            .len = length,
        };
    }

    pub fn toInt(self: Self, comptime T: type) T {
        return @intCast(T, self.value);
    }

    pub fn getLength(self: Self) usize {
        return self.len.toUsize();
    }
};

test "decode u8 array to variable length int" {
    var buf = Buffer(32).init();
    _ = try buf.writer().write(&[4]u8{ 0x81, 0x04, 0x48, 0xad });
    const v_int1 = try VarInt.decode(buf.reader());
    try testing.expectEqual(VarInt.Length.four, v_int1.len);
    try testing.expectEqual(@as(u64, 0x010448ad), v_int1.value);
}

test "encode variable length int to u8 array" {
    const v_int = VarInt{ .value = 0x010448ad, .len = .four };
    var buf = Buffer(32).init();
    try v_int.encode(buf.writer());
    try testing.expectEqual(@as(usize, 4), buf.unreadLength());
    try testing.expectEqualSlices(u8, &[_]u8{ 0x81, 0x04, 0x48, 0xad }, buf.getUnreadSlice());
}

test "convert to variable length int from u64" {
    const v_int = VarInt.fromInt(@intCast(u64, 0x010448ad));
    try testing.expectEqual(
        VarInt{ .value = 0x010448ad, .len = .four },
        v_int,
    );
}

/// Reader that saves its reading history to
/// the inner ArrayList(u8)
pub fn SaveHistoryStream(comptime ReaderType: type) type {
    return struct {
        inner_reader: ReaderType,
        history_array: std.ArrayList(u8),

        pub const Error = ReaderType.Error || mem.Allocator.Error;
        pub const Reader = io.Reader(*Self, Error, read);

        const Self = @This();

        pub fn read(self: *Self, dest: []u8) Error!usize {
            const count = try self.inner_reader.read(dest);
            try self.history_array.appendSlice(dest[0..count]);
            return count;
        }

        pub fn reader(self: *Self) Reader {
            return .{ .context = self };
        }

        pub fn history(self: Self) []const u8 {
            return self.history_array.items;
        }

        pub fn deinit(self: *Self) void {
            self.history_array.deinit();
        }

        pub fn clearAndFree(self: *Self) void {
            self.history_array.clearAndFree();
        }
    };
}

pub fn saveHistoryStream(
    inner_reader: anytype,
    allocator: mem.Allocator,
) SaveHistoryStream(@TypeOf(inner_reader)) {
    return .{
        .inner_reader = inner_reader,
        .history_array = std.ArrayList(u8).init(allocator),
    };
}

const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const io = std.io;
const testing = std.testing;

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

    pub fn encodeInt(value: anytype, writer: anytype) !void {
        const var_int = VarInt.fromInt(value);
        try var_int.encode(writer);
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

    pub fn decodeTo(comptime ReturnType: type, reader: anytype) !ReturnType {
        const var_int = try Self.decode(reader);
        return @intCast(ReturnType, var_int.value);
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

/// return struct that have internal u8 array, read_pos and write_pos.
/// Using read/write methods of this struct adds
/// the number of bytes count read/written to read_pos/write_pos
pub fn Buffer(comptime capacity: comptime_int) type {
    return struct {
        array: [capacity]u8,
        write_pos: usize,
        read_pos: usize,

        const Self = @This();

        const Reader = io.Reader(*Self, BufferError, read);
        const Writer = io.Writer(*Self, BufferError, write);

        pub const BufferError = error{
            NotEnoughUnwrittenLength,
            NotEnoughUnreadLength,
        };

        pub fn init() Self {
            return .{ .array = undefined, .write_pos = 0, .read_pos = 0 };
        }

        /// read bytes as much as possible
        pub fn read(self: *Self, out: []u8) BufferError!usize {
            const unread = self.getUnreadSlice();
            if (out.len > unread.len)
                mem.copy(u8, out, unread)
            else
                mem.copy(u8, out, unread[0..out.len]);
            const count = std.math.min(out.len, unread.len);
            self.read_pos += count;
            return count;
        }

        pub fn reader(self: *Self) Reader {
            return .{ .context = self };
        }

        /// write all bytes from input
        /// if self.array doesn't have enough capacity to write,
        /// return BufferError.NotEnoughRemainCapacity
        pub fn write(self: *Self, input: []const u8) BufferError!usize {
            const unwritten = self.getUnwrittenSlice();
            if (input.len > unwritten.len)
                return BufferError.NotEnoughUnwrittenLength
            else
                mem.copy(u8, unwritten, input);
            self.write_pos += input.len;
            return input.len;
        }

        pub fn writer(self: *Self) Writer {
            return .{ .context = self };
        }

        pub fn getSlice(self: *Self) []u8 {
            return &self.array;
        }

        pub fn getConstSlice(self: *const Self) []const u8 {
            return &self.array;
        }

        /// return IMMUTABLE slice in range self.read_pos .. self.write_pos
        pub fn getUnreadSlice(self: *const Self) []const u8 {
            return self.array[self.read_pos..self.write_pos];
        }

        pub fn unreadLength(self: *const Self) usize {
            const unread_count = self.write_pos - self.read_pos;
            std.debug.assert(unread_count >= 0);
            return unread_count;
        }

        pub fn getUnwrittenSlice(self: *Self) []u8 {
            return self.array[self.write_pos..];
        }

        pub fn unwrittenLength(self: *const Self) usize {
            const unwritten_count = self.array.len - self.write_pos;
            std.debug.assert(unwritten_count >= 0);
            return unwritten_count;
        }

        /// discard n datas without reading
        pub fn discard(self: *Self, n: usize) void {
            self.read_pos += n;
            if (self.read_pos > self.array.len)
                self.read_pos = self.array.len;
        }

        /// read data from reader and write to self
        pub fn readFrom(self: *Self, other_reader: anytype) !void {
            var slice = self.getUnwrittenSlice();
            const n = try other_reader.read(slice);
            self.write_pos += n;
        }

        pub fn realign(self: *Self) void {
            const len = self.unreadLength();
            mem.copy(u8, &self.array, self.getUnreadSlice());
            self.read_pos = 0;
            self.write_pos = len;
        }

        pub fn clear(self: *Self) void {
            self.read_pos = 0;
            self.write_pos = 0;
        }
    };
}

test "Buffer reader and writer" {
    const Buffer32 = Buffer(32);
    var buf = Buffer32.init();
    try testing.expectEqual(@as(usize, 0), buf.unreadLength());
    try testing.expectEqual(@as(usize, 32), buf.unwrittenLength());

    const array1 = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 };
    const array2 = [_]u8{ 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

    const w_cnt1 = try buf.writer().write(&array1);
    const a = try buf.reader().readInt(u32, .Big);
    try testing.expectEqual(@as(usize, 6), w_cnt1);
    try testing.expectEqual(@as(u32, 0x00010203), a);

    const w_cnt2 = try buf.writer().write(&array2);
    var b: [12]u8 = undefined;
    const b_count = try buf.reader().read(&b);
    try testing.expectEqual(@as(usize, 6), w_cnt2);
    try testing.expectFmt(
        "04050A0B0C0D0E0F",
        "{s}",
        .{std.fmt.fmtSliceHexUpper(b[0..b_count])},
    );

    try testing.expectEqual(@as(usize, 8), b_count);
    try testing.expectEqual(@as(usize, 0), buf.unreadLength());
    try testing.expectEqual(@as(usize, 20), buf.unwrittenLength());

    buf.clear();
    try testing.expectEqual(@as(usize, 0), buf.unreadLength());
    try testing.expectEqual(@as(usize, 32), buf.unwrittenLength());
}

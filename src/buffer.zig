const std = @import("std");
const testing = std.testing;
const mem = std.mem;
const io = std.io;

pub const BufferError = error{
    NotEnoughUnwrittenLength,
    NotEnoughUnreadLength,
};

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
        pub fn readFrom(self: *Self, other_reader: anytype) void {
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

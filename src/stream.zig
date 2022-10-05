const std = @import("std");
const io = std.io;
const mem = std.mem;
const math = std.math;
const enums = std.enums;
const testing = std.testing;

const tls = @import("tls.zig");
const Range = @import("range_set.zig").Range;
const RangeSet = @import("range_set.zig").RangeSet;

pub const CryptoStreams = struct {
    streams: StreamsArray,

    const StreamsArray = enums.EnumArray(tls.Epoch, Stream);
    const Self = @This();

    pub fn init(allocator: mem.Allocator) Self {
        var instance = Self{ .streams = StreamsArray.initUndefined() };
        var iter = instance.streams.iterator();
        while (iter.next()) |*s| {
            var ptr = instance.getPtr(s.key);
            ptr.* = Stream.init(allocator);
        }
        return instance;
    }

    pub fn deinit(self: *Self) void {
        var iter = self.streams.iterator();
        while (iter.next()) |*s| {
            s.value.deinit();
        }
    }

    pub fn getPtr(self: *Self, key: tls.Epoch) *Stream {
        return self.streams.getPtr(key);
    }
};

test "CryptoStreams" {
    var cs = CryptoStreams.init(testing.allocator);
    defer cs.deinit();

    var ptr = cs.getPtr(.initial);
    _ = try ptr.sender.write("Hello, World!");
}

pub const Stream = struct {
    reciever: RecvStream,
    sender: SendStream,

    const Self = @This();

    pub fn init(allocator: mem.Allocator) Self {
        return .{
            .reciever = RecvStream.init(allocator),
            .sender = SendStream.init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.reciever.deinit();
        self.sender.deinit();
    }
};

pub const RecvStream = struct {
    data: Queue,
    data_ranges: RangeSet,
    offset: u64 = 0,
    allocator: mem.Allocator,

    const Self = @This();
    const Queue = std.PriorityQueue(RangeBuf, void, rangePriorTo);

    pub const Error = error{
        DataRangeAlreadyIncluded,
    };

    /// compareFn for PriorityQueue
    fn rangePriorTo(context: void, a: RangeBuf, b: RangeBuf) math.Order {
        _ = context;
        const ra = a.range();
        const rb = b.range();

        const ord_s = math.order(ra.start, rb.start);
        if (ord_s != .eq) {
            return ord_s;
        } else {
            return math.order(ra.end, rb.end);
        }
    }

    pub fn init(allocator: mem.Allocator) Self {
        return .{
            .data = Queue.init(allocator, {}),
            .data_ranges = RangeSet.init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.data_ranges.deinit();
        const len = self.data.count();
        for (self.data.items[0..len]) |*buf| {
            buf.deinit(self.allocator);
        }
        self.data.deinit();
    }

    /// push slice buf with offset. buf must be allocated by self.allocator
    pub fn push(
        self: *Self,
        buf: []const u8,
        offset: usize,
    ) (Error || mem.Allocator.Error)!void {
        const r_buf = RangeBuf.fromSlice(buf, offset);
        try self.pushRangeBuf(r_buf);
    }

    pub fn pushRangeBuf(
        self: *Self,
        r_buf: RangeBuf,
    ) mem.Allocator.Error!void {
        const buf_range = r_buf.range();
        if (self.data_ranges.include(buf_range)) {
            return;
        }

        try self.data.add(r_buf);
        try self.data_ranges.add(buf_range);
    }

    pub fn read(self: *Self, out: []u8) !usize {
        var top_buf: RangeBuf = undefined;

        while (self.data.peek()) |top| {
            if (top.range().end <= self.offset) {
                var removed = self.data.remove();
                defer removed.deinit(self.allocator);
            } else {
                top_buf = top;
                break;
            }
        } else return 0;

        if (top_buf.getSliceWithOffset(self.offset)) |slice| {
            const copy_len = math.min(out.len, slice.len);
            mem.copy(u8, out, slice[0..copy_len]);
            self.offset += copy_len;

            if (top_buf.range().end <= self.offset) {
                var removed = self.data.remove();
                removed.deinit(self.allocator);
            }

            return copy_len;
        } else {
            return 0;
        }
    }

    pub const Reader = io.Reader(*Self, ReadError, read);
    pub const ReadError = error{};

    pub fn reader(self: *Self) Reader {
        return .{ .context = self };
    }
};

test "RecvStream -- push and read" {
    var rs = RecvStream.init(testing.allocator);
    defer rs.deinit();
    const b1 = RangeBuf.fromSlice(
        try testing.allocator.dupe(u8, "1234567890"),
        0,
    );
    const b2 = RangeBuf.fromSlice(
        try testing.allocator.dupe(u8, "90abcdef"),
        8,
    );
    const b3 = RangeBuf.fromSlice(
        try testing.allocator.dupe(u8, "efABCDEFGH"), // 24
        14,
    );
    try rs.pushRangeBuf(b1);
    try rs.pushRangeBuf(b2);
    try rs.pushRangeBuf(b3);
    try testing.expectError(
        error.DataRangeAlreadyIncluded,
        rs.pushRangeBuf(b3),
    );

    var read_buf = [_]u8{0} ** 256;
    var count = try rs.read(&read_buf);
    try testing.expectEqualStrings(
        "1234567890",
        read_buf[0..count],
    );

    count = try rs.read(&read_buf);
    try testing.expectEqualStrings(
        "abcdef",
        read_buf[0..count],
    );

    count = try rs.read(&read_buf);
    try testing.expectEqualStrings(
        "ABCDEFGH",
        read_buf[0..count],
    );

    const b4 = RangeBuf.fromSlice(
        try testing.allocator.dupe(u8, "012345"),
        30,
    );
    const b5 = RangeBuf.fromSlice(
        try testing.allocator.dupe(u8, "abcdef"),
        24,
    );

    try rs.pushRangeBuf(b4);
    count = try rs.read(&read_buf);
    try testing.expectEqualStrings("", read_buf[0..count]);

    try rs.pushRangeBuf(b5);
    count = try rs.read(&read_buf);
    try testing.expectEqualStrings("abcdef", read_buf[0..count]);
}

pub const SendStream = struct {
    data: Queue,
    offset: u64 = 0,
    end_offset: u64 = 0,
    allocator: mem.Allocator,

    const Queue = std.fifo.LinearFifo(RangeBuf, .Dynamic);
    const Self = @This();

    pub fn init(allocator: mem.Allocator) Self {
        return .{
            .data = Queue.init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        var i: usize = 0;
        while (i < self.data.count) : (i += 1) {
            var buf = self.data.peekItem(i);
            buf.deinit(self.allocator);
        }
        self.data.deinit();
    }

    pub fn emit(self: *Self, max_len: usize, allocator: mem.Allocator) !?RangeBuf {
        if (self.data.count == 0)
            return null;
        var r_buf = self.data.peekItem(0);
        const pos = @intCast(usize, self.offset - r_buf.offset);
        const len =
            math.min(max_len, r_buf.buf.len - pos);

        const copy = try allocator.dupe(u8, r_buf.buf[pos .. pos + len]);
        const offset = self.offset;
        self.offset += len;

        if (r_buf.endOffset() <= self.offset) {
            r_buf.deinit(self.allocator);
            self.data.discard(1);
        }

        return RangeBuf.fromSlice(copy, offset);
    }

    pub const WriteError = error{OutOfMemory};
    pub const Writer = io.Writer(*Self, WriteError, write);

    pub fn write(self: *Self, buf: []const u8) WriteError!usize {
        const copy = try self.allocator.dupe(u8, buf);
        const range_buf = RangeBuf.fromSlice(copy, self.end_offset);
        self.end_offset += buf.len;

        try self.data.writeItem(range_buf);
        return buf.len;
    }

    pub fn writer(self: *Self) Writer {
        return .{ .context = self };
    }
};

test "SendStream -- write and emit" {
    const allocator = testing.allocator;
    var ss = SendStream.init(allocator);
    defer ss.deinit();

    _ = try ss.writer().write("hello, world.");
    _ = try ss.writer().write("abcdef");
    _ = try ss.writer().write("0123456789");

    var buf1 = (try ss.emit(5, allocator)).?;
    defer buf1.deinit(allocator);
    try testing.expectEqualStrings("hello", buf1.buf);

    var buf2 = (try ss.emit(500, allocator)).?;
    defer buf2.deinit(allocator);
    try testing.expectEqualStrings(", world.", buf2.buf);

    var buf3 = (try ss.emit(500, allocator)).?;
    defer buf3.deinit(allocator);
    try testing.expectEqualStrings("abcdef", buf3.buf);

    var buf4 = (try ss.emit(5, allocator)).?;
    defer buf4.deinit(allocator);
    try testing.expectEqualStrings("01234", buf4.buf);

    var buf5 = (try ss.emit(2, allocator)).?;
    defer buf5.deinit(allocator);
    try testing.expectEqualStrings("56", buf5.buf);

    var buf6 = (try ss.emit(3, allocator)).?;
    defer buf6.deinit(allocator);
    try testing.expectEqualStrings("789", buf6.buf);
}

pub const RangeBuf = struct {
    buf: []const u8,
    offset: u64,

    const Self = @This();

    const Error = error{};

    pub fn fromSlice(buf: []const u8, offset: usize) Self {
        return .{
            .buf = buf,
            .offset = offset,
        };
    }

    pub fn deinit(self: *Self, allocator: mem.Allocator) void {
        allocator.free(self.buf);
    }

    pub fn range(self: Self) Range {
        const off = @intCast(u64, self.offset);
        return Range.from(
            off,
            off + self.buf.len,
        );
    }

    pub fn endOffset(self: Self) u64 {
        return self.offset + @intCast(u64, self.buf.len);
    }

    pub fn getSliceWithOffset(self: Self, offset: u64) ?[]const u8 {
        if (offset < self.offset)
            return null;

        const pos = @intCast(usize, offset - self.offset);
        return self.buf[math.min(pos, self.buf.len)..];
    }
};

test "RangeBuf -- getSliceWithOffset" {
    var a = "0123456789";
    var buf = RangeBuf.fromSlice(a, 10);

    try testing.expectEqual(null, buf.getSliceWithOffset(5));
    try testing.expectEqualStrings(a, buf.getSliceWithOffset(10).?);
    try testing.expectEqualStrings(a[2..], buf.getSliceWithOffset(12).?);
    try testing.expectEqualStrings(a[10..], buf.getSliceWithOffset(20).?);
    try testing.expectEqualStrings(&[_]u8{}, buf.getSliceWithOffset(25).?);
}

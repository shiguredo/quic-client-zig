const std = @import("std");
const io = std.io;
const mem = std.mem;
const math = std.math;
const enums = std.enums;
const testing = std.testing;

const tls = @import("tls.zig");
const Range = @import("range_set.zig").Range;
const RangeSet = @import("range_set.zig").RangeSet;

pub const CryptoStreams = enums.EnumArray(tls.Epoch, std.ArrayList(u8));

pub const Stream = struct {};

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
    ) (Error || mem.Allocator.Error)!void {
        const buf_range = r_buf.range();
        if (self.data_ranges.include(buf_range)) {
            return Error.DataRangeAlreadyIncluded;
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

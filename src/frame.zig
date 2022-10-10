const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const util = @import("util.zig");
const tls = @import("tls.zig");
const RangeBuf = @import("stream.zig").RangeBuf;
const Stream = @import("stream.zig").Stream;
const VariableLengthInt = util.VariableLengthInt;
const RangeSet = @import("range_set.zig").RangeSet;

pub const FrameTypes = enum {
    padding,
    ack,
    crypto,
    stream,
    handshake_done,
};

pub const Frame = union(FrameTypes) {
    padding: PaddingFrame,
    ack: AckFrame,
    crypto: CryptoFrame,
    stream: StreamFrame,
    handshake_done: HandshakeDoneFrame,

    const Self = @This();

    pub fn deinit(self: *Self) void {
        switch (self.*) {
            .ack => |*f| f.deinit(),
            .crypto => |*f| f.deinit(),
            else => {},
        }
    }

    pub fn encode(self: *const Self, writer: anytype) !void {
        return switch (self.*) {
            .ack => |f| f.encode(writer),
            .padding => |f| f.encode(writer),
            .crypto => |f| f.encode(writer),
            else => unreachable, // TODO: implement
        };
    }

    pub fn decode(reader: anytype, allocator: mem.Allocator) !Self {
        const type_id = try VariableLengthInt.decode(reader);
        return switch (type_id.value) {
            0x02...0x03 => Self{
                .ack = try AckFrame.decodeAfterType(type_id, reader, allocator),
            },
            0x06 => Self{
                .crypto = try CryptoFrame.decodeAfterType(reader, allocator),
            },
            else => unreachable, // TODO: implement for other frames
        };
    }
};

pub const PaddingFrame = struct {
    length: usize,

    const Self = @This();

    pub fn init(length: usize) Self {
        return .{ .length = length };
    }

    pub fn encode(self: Self, writer: anytype) @TypeOf(writer).Error!void {
        try writer.writeByteNTimes(0, self.length);
    }
};

pub const AckFrame = struct {
    largest_ack: VariableLengthInt,
    ack_delay: VariableLengthInt,
    first_ack_range: VariableLengthInt,
    ack_ranges: std.ArrayList(AckRange),
    ecn_counts: ?EcnCounts = null,

    pub const AckRange = struct {
        gap: VariableLengthInt,
        ack_range_length: VariableLengthInt,
    };

    pub const EcnCounts = struct {
        ect0: VariableLengthInt,
        ect1: VariableLengthInt,
        ecn_cn: VariableLengthInt,
    };

    const Self = @This();

    pub fn deinit(self: *Self) void {
        self.ack_ranges.deinit();
    }

    pub fn encode(self: *const Self, writer: anytype) !void {
        const type_id =
            if (self.ecn_counts) |_| try VariableLengthInt.fromInt(0x03) else try VariableLengthInt.fromInt(0x02);
        try type_id.encode(writer);
        try self.largest_ack.encode(writer);
        try self.ack_delay.encode(writer);
        const ack_range_count = try VariableLengthInt.fromInt(self.ack_ranges.items.len);
        try ack_range_count.encode(writer);
        try self.first_ack_range.encode(writer);

        if (self.ecn_counts) |ecn_counts| {
            try ecn_counts.ect0.encode(writer);
            try ecn_counts.ect1.encode(writer);
            try ecn_counts.ecn_cn.encode(writer);
        }
    }

    pub fn decodeAfterType(
        type_id: VariableLengthInt,
        reader: anytype,
        allocator: mem.Allocator,
    ) !Self {
        const largest = try VariableLengthInt.decode(reader);
        const delay = try VariableLengthInt.decode(reader);
        const range_count = try VariableLengthInt.decode(reader);
        const first_range = try VariableLengthInt.decode(reader);
        const ranges = ranges: {
            var ranges = try std.ArrayList(AckRange).initCapacity(allocator, range_count.toInt(usize));
            var i: usize = 0;
            while (i < range_count.value) : (i += 1) {
                const gap = try VariableLengthInt.decode(reader);
                const length = try VariableLengthInt.decode(reader);
                try ranges.append(.{ .gap = gap, .ack_range_length = length });
            }
            break :ranges ranges;
        };

        const ecn_counts = if (type_id.value & 0x01 == 0x01) EcnCounts{
            .ect0 = try VariableLengthInt.decode(reader),
            .ect1 = try VariableLengthInt.decode(reader),
            .ecn_cn = try VariableLengthInt.decode(reader),
        } else null;

        return Self{
            .largest_ack = largest,
            .ack_delay = delay,
            .first_ack_range = first_range,
            .ack_ranges = ranges,
            .ecn_counts = ecn_counts,
        };
    }

    pub fn fromRangeSet(set: RangeSet, delay: u64, allocator: mem.Allocator) !?Self {
        const count = set.count();
        if (count == 0) return null;

        var instance: Self = undefined;
        instance.ack_ranges = std.ArrayList(AckRange).init(allocator);
        instance.ecn_counts = null;
        errdefer instance.ack_ranges.deinit();
        instance.ack_delay = try VariableLengthInt.fromInt(delay);
        const largest = set.ranges.items[count - 1];
        instance.largest_ack = try VariableLengthInt.fromInt(largest.end - 1);
        instance.first_ack_range =
            try VariableLengthInt.fromInt(largest.end - largest.start);

        var prev_smallest = largest.start;

        if (count < 2) return instance;

        var i = count - 2;
        while (i >= 0) : (i -= 1) {
            const r = set.ranges.items[i];
            const gap = prev_smallest - r.end - 1;
            const range_len = r.end - r.start;
            try instance.ack_ranges.append(.{
                .gap = try VariableLengthInt.fromInt(gap),
                .ack_range_length = try VariableLengthInt.fromInt(range_len),
            });

            if (i == 0) break;
            prev_smallest = r.start;
        }

        return instance;
    }
};

test "AckFrame -- fromRangeSet()" {
    var rset = RangeSet.init(testing.allocator);
    defer rset.deinit();
    try rset.add(.{ .start = 0, .end = 100 });
    try rset.add(.{ .start = 150, .end = 200 });
    try rset.add(.{ .start = 250, .end = 300 });

    var actual = (try AckFrame.fromRangeSet(rset, 0, testing.allocator)).?;
    defer actual.deinit();
    var expect = AckFrame{
        .largest_ack = try VariableLengthInt.fromInt(299),
        .ack_delay = try VariableLengthInt.fromInt(0),
        .first_ack_range = try VariableLengthInt.fromInt(50),
        .ack_ranges = r: {
            var arr = std.ArrayList(AckFrame.AckRange).init(testing.allocator);
            try arr.appendSlice(&[_]AckFrame.AckRange{
                .{
                    .gap = try VariableLengthInt.fromInt(49),
                    .ack_range_length = try VariableLengthInt.fromInt(50),
                },
                .{
                    .gap = try VariableLengthInt.fromInt(49),
                    .ack_range_length = try VariableLengthInt.fromInt(100),
                },
            });
            break :r arr;
        },
        .ecn_counts = null,
    };
    defer expect.deinit();
    try testing.expectEqual(expect.largest_ack, actual.largest_ack);
    try testing.expectEqual(expect.ack_delay, actual.ack_delay);
    try testing.expectEqual(expect.first_ack_range, actual.first_ack_range);
    try testing.expectEqualSlices(
        AckFrame.AckRange,
        expect.ack_ranges.items,
        actual.ack_ranges.items,
    );
}

pub const CryptoFrame = struct { // type_id: 0x06
    offset: VariableLengthInt,
    data: []const u8,
    allocator: mem.Allocator,

    const Self = @This();

    /// takes RangeBuf's ownership
    pub fn fromRangeBuf(b: RangeBuf, allocator: mem.Allocator) !Self {
        return .{
            .offset = try VariableLengthInt.fromInt(b.offset),
            .data = b.buf,
            .allocator = allocator,
        };
    }

    pub fn fromStream(s: *Stream, max_len: usize, allocator: mem.Allocator) ?Self {
        const b =
            try s.sender.emit(max_len, allocator) orelse return null;
        return try Self.fromRangeBuf(b, allocator);
    }

    pub fn deinit(self: Self) void {
        self.allocator.free(self.data);
    }

    pub fn encode(self: Self, writer: anytype) (@TypeOf(writer).Error || VariableLengthInt.Error)!void {
        const frame_type = try VariableLengthInt.fromInt(0x06);
        try frame_type.encode(writer);
        try self.offset.encode(writer);
        const length = try VariableLengthInt.fromInt(self.data.len);
        try length.encode(writer);
        try writer.writeAll(self.data);
    }

    pub fn decodeAfterType(reader: anytype, allocator: mem.Allocator) !Self {
        const offset = try VariableLengthInt.decode(reader);
        const length = try VariableLengthInt.decode(reader);
        const data = data: {
            var buf = try allocator.alloc(u8, @intCast(usize, length.value));
            errdefer allocator.free(buf);
            try reader.readNoEof(buf);
            break :data buf;
        };
        return Self{
            .offset = offset,
            .data = data,
            .allocator = allocator,
        };
    }
};

pub const StreamFrame = struct {
    type_id: VariableLengthInt,
    stream_id: VariableLengthInt,
    offset: VariableLengthInt,
    length: VariableLengthInt,
    data: std.ArrayList(u8),
};

pub const HandshakeDoneFrame = struct {};

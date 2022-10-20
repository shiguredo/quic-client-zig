const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const util = @import("util.zig");
const tls = @import("tls.zig");
const RangeBuf = @import("stream.zig").RangeBuf;
const Stream = @import("stream.zig").Stream;
const VarInt = util.VarInt;
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
        const type_id = try VarInt.decode(reader);
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
    largest_ack: VarInt,
    ack_delay: VarInt,
    first_ack_range: VarInt,
    ack_ranges: std.ArrayList(AckRange),
    ecn_counts: ?EcnCounts = null,

    pub const AckRange = struct {
        gap: VarInt,
        ack_range_length: VarInt,
    };

    pub const EcnCounts = struct {
        ect0: VarInt,
        ect1: VarInt,
        ecn_cn: VarInt,
    };

    const Self = @This();

    pub fn deinit(self: *Self) void {
        self.ack_ranges.deinit();
    }

    pub fn encode(self: *const Self, writer: anytype) !void {
        const type_id =
            if (self.ecn_counts) |_| VarInt.fromInt(0x03) else VarInt.fromInt(0x02);
        try type_id.encode(writer);
        try self.largest_ack.encode(writer);
        try self.ack_delay.encode(writer);
        const ack_range_count = VarInt.fromInt(self.ack_ranges.items.len);
        try ack_range_count.encode(writer);
        try self.first_ack_range.encode(writer);

        if (self.ecn_counts) |ecn_counts| {
            try ecn_counts.ect0.encode(writer);
            try ecn_counts.ect1.encode(writer);
            try ecn_counts.ecn_cn.encode(writer);
        }
    }

    pub fn decodeAfterType(
        type_id: VarInt,
        reader: anytype,
        allocator: mem.Allocator,
    ) !Self {
        const largest = try VarInt.decode(reader);
        const delay = try VarInt.decode(reader);
        const range_count = try VarInt.decode(reader);
        const first_range = try VarInt.decode(reader);
        const ranges = ranges: {
            var ranges = try std.ArrayList(AckRange).initCapacity(allocator, range_count.toInt(usize));
            var i: usize = 0;
            while (i < range_count.value) : (i += 1) {
                const gap = try VarInt.decode(reader);
                const length = try VarInt.decode(reader);
                try ranges.append(.{ .gap = gap, .ack_range_length = length });
            }
            break :ranges ranges;
        };

        const ecn_counts = if (type_id.value & 0x01 == 0x01) EcnCounts{
            .ect0 = try VarInt.decode(reader),
            .ect1 = try VarInt.decode(reader),
            .ecn_cn = try VarInt.decode(reader),
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
        instance.ack_delay = VarInt.fromInt(delay);
        const largest = set.ranges.items[count - 1];
        instance.largest_ack = VarInt.fromInt(largest.end - 1);
        instance.first_ack_range =
            VarInt.fromInt(largest.end - largest.start);

        var prev_smallest = largest.start;

        if (count < 2) return instance;

        var i = count - 2;
        while (i >= 0) : (i -= 1) {
            const r = set.ranges.items[i];
            const gap = prev_smallest - r.end - 1;
            const range_len = r.end - r.start;
            try instance.ack_ranges.append(.{
                .gap = VarInt.fromInt(gap),
                .ack_range_length = VarInt.fromInt(range_len),
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
        .largest_ack = VarInt.fromInt(299),
        .ack_delay = VarInt.fromInt(0),
        .first_ack_range = VarInt.fromInt(50),
        .ack_ranges = r: {
            var arr = std.ArrayList(AckFrame.AckRange).init(testing.allocator);
            try arr.appendSlice(&[_]AckFrame.AckRange{
                .{
                    .gap = VarInt.fromInt(49),
                    .ack_range_length = VarInt.fromInt(50),
                },
                .{
                    .gap = VarInt.fromInt(49),
                    .ack_range_length = VarInt.fromInt(100),
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
    offset: VarInt,
    data: []const u8,
    allocator: mem.Allocator,

    const Self = @This();

    /// takes RangeBuf's ownership
    pub fn fromRangeBuf(b: RangeBuf, allocator: mem.Allocator) !Self {
        return .{
            .offset = VarInt.fromInt(b.offset),
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

    pub fn encode(self: Self, writer: anytype) (@TypeOf(writer).Error || VarInt.Error)!void {
        const frame_type = VarInt.fromInt(0x06);
        try frame_type.encode(writer);
        try self.offset.encode(writer);
        const length = VarInt.fromInt(self.data.len);
        try length.encode(writer);
        try writer.writeAll(self.data);
    }

    pub fn decodeAfterType(reader: anytype, allocator: mem.Allocator) !Self {
        const offset = try VarInt.decode(reader);
        const length = try VarInt.decode(reader);
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
    type_id: VarInt,
    stream_id: VarInt,
    offset: VarInt,
    length: VarInt,
    data: std.ArrayList(u8),
};

pub const HandshakeDoneFrame = struct {};

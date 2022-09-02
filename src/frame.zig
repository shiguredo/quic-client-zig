const std = @import("std");
const mem = std.mem;
const util = @import("util.zig");
const tls = @import("tls.zig");

const VariableLengthInt = util.VariableLengthInt;

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
    type_id: VariableLengthInt, // 0x02 ... 0x03
    largest_ack: VariableLengthInt,
    ack_delay: VariableLengthInt,
    ack_range_count: VariableLengthInt,
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

    pub fn encode(self: *const Self, writer: anytype) !usize {
        // TODO: implement
        _ = self;
        _ = writer;
        return 0;
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
            var ranges = std.ArrayList(AckRange).init(allocator);
            try ranges.ensureTotalCapacity(@intCast(usize, range_count.value));
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
            .type_id = type_id,
            .largest_ack = largest,
            .ack_delay = delay,
            .ack_range_count = range_count,
            .first_ack_range = first_range,
            .ack_ranges = ranges,
            .ecn_counts = ecn_counts,
        };
    }
};

pub const CryptoFrame = struct { // type_id: 0x06
    offset: VariableLengthInt,
    data: std.ArrayList(u8),

    const Self = @This();

    pub fn deinit(self: Self) void {
        self.data.deinit();
    }

    pub fn encode(self: Self, writer: anytype) (@TypeOf(writer).Error || VariableLengthInt.Error)!void {
        const frame_type = try VariableLengthInt.fromInt(0x06);
        try frame_type.encode(writer);
        try self.offset.encode(writer);
        const length = try VariableLengthInt.fromInt(self.data.items.len);
        try length.encode(writer);
        try writer.writeAll(self.data.items);
    }

    pub fn decodeAfterType(reader: anytype, allocator: mem.Allocator) !Self {
        const offset = try VariableLengthInt.decode(reader);
        const length = try VariableLengthInt.decode(reader);
        const data = data: {
            var buf = try allocator.alloc(u8, @intCast(usize, length.value));
            try reader.readNoEof(buf);
            break :data std.ArrayList(u8).fromOwnedSlice(allocator, buf);
        };
        return Self{
            .offset = offset,
            .data = data,
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

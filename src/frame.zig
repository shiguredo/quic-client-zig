const std = @import("std");
const util = @import("util.zig");
const tls = @import("tls.zig");

const ArrayList = std.ArrayList;
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

    pub fn encode(self: *const Self, writer: anytype) !void {
        return switch (self.*) {
            .padding => |f| f.encode(writer),
            .crypto => |f| f.encode(writer),
            else => unreachable, // TODO: implement
        };
    }
};

pub const PaddingFrame = struct {
    length: usize,

    const Self = @This();

    pub fn init(length: usize) Self {
        return .{.length = length};
    }

    pub fn encode(self: Self, writer: anytype) @TypeOf(writer).Error!void {
        try writer.writeByteNTimes(0, self.length);
    }
};

pub const AckFrame = struct {
    type_id: VariableLengthInt,
    largest_acknowledged: VariableLengthInt,
    ack_delay: VariableLengthInt,
    ack_range_count: VariableLengthInt,
    first_ack_range: VariableLengthInt,
    ack_ranges: ArrayList(AckRange),
    ecn_counts: EcnCounts,

    const AckRange = struct {
        gap: VariableLengthInt,
        ack_range_length: VariableLengthInt,
    };

    const EcnCounts = struct {
        ect0: VariableLengthInt,
        ect1: VariableLengthInt,
        ecn_cn: VariableLengthInt,
    };

    const Self = @This();

    pub fn encode(self: *const Self, writer: anytype) !usize {
        // TODO: implement
        _ = self;
        _ = writer;
        return 0;
    }
};

pub const CryptoFrame = struct {
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
};

pub const StreamFrame = struct {
    type_id: VariableLengthInt,
    stream_id: VariableLengthInt,
    offset: VariableLengthInt,
    length: VariableLengthInt,
    data: std.ArrayList(u8),
};

pub const HandshakeDoneFrame = struct {};

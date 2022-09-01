const std = @import("std");
const mem = std.mem;

const util = @import("../../util.zig");

/// https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-encodin
/// ```
/// Transport Parameter {
///   Transport Parameter ID (i),
///   Transport Parameter Length (i),
///   Transport Parameter Value (..),
/// }
/// ```
pub const QuicTransportParameters = struct {
    parameter_data: std.ArrayList(u8),

    const Self = @This();

    pub fn init(allocator: mem.Allocator) Self {
        return .{ .parameter_data = std.ArrayList(u8).init(allocator) };
    }

    pub fn deinit(self: Self) void {
        self.parameter_data.deinit();
    }

    pub fn appendParam(
        self: *Self,
        param_id: TransportParameterId,
        value: []const u8,
    ) !void {
        const vl_int_id = try util.VariableLengthInt.fromInt(@enumToInt(param_id));
        var writer = self.parameter_data.writer();
        try vl_int_id.encode(writer);
        const vl_int_length = try util.VariableLengthInt.fromInt(value.len);
        try vl_int_length.encode(writer);
        try writer.writeAll(value);
    }

    pub fn getEncLen(self: Self) usize {
        return self.parameter_data.items.len;
    }

    pub fn encode(self: Self, writer: anytype) @TypeOf(writer).Error!void {
        try writer.writeAll(self.parameter_data.items);
    }
};

/// see https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-definit
pub const TransportParameterId = enum(u32) {
    original_dcid = 0x00,
    max_idle_timeout = 0x01,
    stateless_reset_token = 0x02,
    max_udp_payload_size = 0x03,
    initial_max_data = 0x04,
    initial_max_stream_data_bidi_local = 0x05,
    initial_max_stream_data_bidi_remote = 0x06,
    initial_max_stream_data_uni = 0x07,
    initial_max_streams_bidi = 0x08,
    initial_max_streams_uni = 0x09,
    ack_delay_exponent = 0x0a,
    max_ack_delay = 0x0b,
    disable_active_migration = 0x0c,
    preferred_address = 0x0d,
    active_cid_limit = 0x0e,
    initial_scid = 0x0f,
    retry_source_connection_id = 0x10,
};

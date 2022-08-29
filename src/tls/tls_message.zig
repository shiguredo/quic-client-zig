const Handshake = @import("handshake.zig");

pub const TlsMessageType = enum {
    handshake,
};

pub const TlsMessage = struct {
    handshake: Handshake,

    const Self = @This();

    pub fn getEncLen(self: *const Self) usize {
        return switch (self.*) {
            .handshake => |*m| m.getEncLen(),
        };
    }

    /// encode self to writer
    pub fn encode(self: *const Self, writer: anytype) @TypeOf(writer).Error!void {
        return switch (self.*) {
            .handshake => |*m| m.encode(writer),
        };
    }
};

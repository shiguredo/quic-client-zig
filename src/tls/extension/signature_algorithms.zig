const std = @import("std");

const SignatureScheme = @import("../extension.zig").SignatureScheme;

pub const SignatureAlgorithms = struct {
    const Algorithms = std.BoundedArray(SignatureScheme, 65536 / @sizeOf(SignatureScheme));
    supported_algorithms: Algorithms,

    const Self = @This();

    pub fn init() Self {
        var supports = Algorithms.init(0) catch unreachable;
        return Self{
            .supported_algorithms = supports,
        };
    }

    pub fn append(self: *Self, scheme: SignatureScheme) error{Overflow}!void {
        try self.supported_algorithms.append(scheme);
    }

    pub fn appendSlice(self: *Self, schemes: []const SignatureScheme) error{Overflow}!void {
        try self.supported_algorithms.appendSlice(schemes);
    }

    /// get encoded bytes size
    pub fn getEncLen(self: *const Self) usize {
        var len: usize = 0;
        len += @sizeOf(u16); // length field
        len += @sizeOf(SignatureScheme) * self.supported_algorithms.len;
        return len;
    }

    /// encode self to writer
    pub fn encode(self: *const Self, writer: anytype) @TypeOf(writer).Error!void {
        const slice = self.supported_algorithms.constSlice();

        try writer.writeIntBig(u16, @intCast(u16, slice.len * @sizeOf(u16)));
        for (slice) |algo| {
            try writer.writeIntBig(u16, @enumToInt(algo));
        }
    }
};

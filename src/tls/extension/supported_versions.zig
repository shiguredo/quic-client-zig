const std = @import("std");

/// only tls 1.3 is supported
pub const SupportedVersions = struct {
    const Versions = std.BoundedArray(u16, 128);

    versions: Versions,

    pub const TLS13 = 0x0304;
    const Self = @This();

    pub fn init() Self {
        return .{ .versions = Versions.init(0) catch unreachable };
    }

    pub fn append(self: *Self, version: u16) error{Overflow}!void {
        try self.versions.append(version);
    }

    /// get encoded bytes size
    pub fn getEncLen(self: *const Self) usize {
        return blk: {
            var temp: usize = 0;
            temp += @sizeOf(u8);
            temp += @sizeOf(u16) * self.versions.len;
            break :blk temp;
        };
    }

    /// encode self to writer
    pub fn encode(self: *const Self, writer: anytype) @TypeOf(writer).Error!void {
        try writer.writeIntBig(u8, @as(u8, @sizeOf(u16)));
        for (self.versions.constSlice()) |version| {
            try writer.writeIntBig(u16, @as(u16, version));
        }
    }
};

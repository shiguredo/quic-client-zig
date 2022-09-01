const std = @import("std");
const HandshakeType = @import("../handshake.zig").HandshakeType;

/// only tls 1.3 is supported
pub const SupportedVersions = struct {
    const Versions = std.BoundedArray(u16, 128);

    msg_type: HandshakeType,
    versions: Versions,
    selected_version: ?u16,

    pub const TLS13 = 0x0304;
    const Self = @This();

    pub const Error = error{EncodeFailed};

    pub fn init(msg_type: HandshakeType) Self {
        return .{
            .msg_type = msg_type,
            .versions = Versions.init(0) catch unreachable,
            .selected_version = null,
        };
    }

    pub fn append(self: *Self, version: u16) error{Overflow}!void {
        try self.versions.append(version);
    }

    /// get encoded bytes size
    pub fn getEncLen(self: *const Self) usize {
        return switch (self.msg_type) {
            .client_hello => client: {
                var temp: usize = 0;
                temp += @sizeOf(u8);
                temp += @sizeOf(u16) * self.versions.len;
                break :client temp;
            },
            .server_hello => @as(usize, @sizeOf(u16)),
        };
    }

    pub fn encode(self: Self, writer: anytype) !void {
        switch (self.msg_type) {
            .client_hello => try self.encodeClient(writer),
            .server_hello => try self.encodeServer(writer),
        }
    }

    fn encodeClient(self: Self, writer: anytype) !void {
        try writer.writeIntBig(u8, @intCast(u8, self.versions.len * 2));
        for (self.versions.constSlice()) |version| {
            try writer.writeIntBig(u16, @as(u16, version));
        }
    }

    fn encodeServer(self: Self, writer: anytype) !void {
        if (self.selected_version) |sv|
            try writer.writeIntBig(u16, sv)
        else
            return Error.EncodeFailed;
    }

    pub fn decode(msg_type: HandshakeType, reader: anytype) !Self {
        return switch (msg_type) {
            .client_hello => try Self.decodeClient(reader),
            .server_hello => try Self.decodeServer(reader),
        };
    }

    pub fn decodeClient(reader: anytype) !Self {
        var instance = Self.init(.client_hello);

        const len = @intCast(u64, try reader.readIntBig(u8));
        var stream = std.io.limitedReader(reader, len);
        var s_reader = stream.reader();

        while (s_reader.readIntBig(u16)) |val| {
            try instance.versions.append(val);
        } else |err| switch (err) {
            error.EndOfStream => {}, // skip
            else => return err,
        }

        return instance;
    }

    pub fn decodeServer(reader: anytype) !Self {
        var instance = Self.init(.server_hello);
        const version = try reader.readIntBig(u16);
        instance.selected_version = version;
        return instance;
    }
};

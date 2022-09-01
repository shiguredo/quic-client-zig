const std = @import("std");
const mem = std.mem;
const io = std.io;
const enums = std.enums;
const NamedGroup = @import("../extension.zig").NamedGroup;
const HandshakeType = @import("../handshake.zig").HandshakeType;

pub const KeyShare = struct {
    const Shares = std.ArrayList(KeyShareEntry);

    msg_type: HandshakeType,
    shares: Shares,
    server_share: ?KeyShareEntry,

    const Self = @This();

    pub const KeyShareEntry = struct {
        group: NamedGroup,
        key_exchange: std.ArrayList(u8),
    };

    pub const Error = error{
        DecodeFailed,
        InvalidGroup,
    };

    pub fn init(msg_type: HandshakeType, allocator: mem.Allocator) Self {
        var shares = Shares.init(allocator);
        return Self{
            .msg_type = msg_type,
            .shares = shares,
            .server_share = null,
        };
    }

    pub fn deinit(self: Self) void {
        for (self.shares.items) |entry| {
            entry.key_exchange.deinit();
        }
        self.shares.deinit();
        if (self.server_share) |s_share| s_share.key_exchange.deinit();
    }

    pub fn append(self: *Self, entry: KeyShareEntry) mem.Allocator.Error!void {
        try self.shares.append(entry);
    }

    pub fn appendSlice(self: *Self, entries: []const KeyShareEntry) mem.Allocator.Error!void {
        try self.shares.appendSlice(entries);
    }

    /// get encoded bytes size
    pub fn getEncLen(self: Self) usize {
        var len: usize = 0;
        len += @sizeOf(u16);
        for (self.shares.items) |*share| {
            len += @sizeOf(NamedGroup); // share group field
            len += @sizeOf(u16); // share length field
            len += share.key_exchange.items.len;
        }
        return len;
    }

    pub fn encode(self: Self, writer: anytype) !void {
        switch (self.msg_type) {
            .client_hello => try self.encodeClient(writer),
            .server_hello => unreachable, // TODO: implement encodeServer()
        }
    }

    fn encodeClient(self: Self, writer: anytype) !void {
        std.debug.assert(self.msg_type == .client_hello);
        var length: usize = 0;
        for (self.shares.items) |*share| {
            length += @sizeOf(u16) * 2;
            length += share.key_exchange.items.len;
        }
        try writer.writeIntBig(u16, @intCast(u16, length));

        for (self.shares.items) |*share| {
            try writer.writeIntBig(u16, @enumToInt(share.group));
            try writer.writeIntBig(u16, @intCast(u16, share.key_exchange.items.len));
            _ = try writer.write(share.key_exchange.items);
        }
    }

    pub fn decode(msg_type: HandshakeType, reader: anytype, allocator: mem.Allocator) !Self {
        return switch (msg_type) {
            .client_hello => unreachable, // TODO: implement decodeClient
            .server_hello => try Self.decodeServer(reader, allocator),
        };
    }

    pub fn decodeServer(reader: anytype, allocator: mem.Allocator) !Self {
        var instance = Self.init(.server_hello, allocator);
        const group = try NamedGroup.cast(try reader.readIntBig(u16));
        const len = try reader.readIntBig(u16);
        var share = try allocator.alloc(u8, @intCast(usize, len));
        try reader.readNoEof(share);
        const share_list = std.ArrayList(u8).fromOwnedSlice(allocator, share);
        instance.server_share = KeyShareEntry{
            .group = group,
            .key_exchange = share_list,
        };

        return instance;
    }
};

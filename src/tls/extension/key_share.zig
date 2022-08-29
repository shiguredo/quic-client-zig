const std = @import("std");
const mem = std.mem;
const NamedGroup = @import("../extension.zig").NamedGroup;

pub const KeyShare = struct {
    const Shares = std.ArrayList(KeyShareEntry);

    shares: Shares,

    const Self = @This();

    pub const KeyShareEntry = struct {
        group: NamedGroup,
        key_exchange: std.ArrayList(u8),
    };

    pub fn init(allocator: mem.Allocator) Self {
        var shares = Shares.init(allocator);

        return Self{
            .shares = shares,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.shares.items) |entry| {
            entry.key_exchange.deinit();
        }
        self.shares.deinit();
    }

    pub fn append(self: *Self, entry: KeyShareEntry) mem.Allocator.Error!void {
        try self.shares.append(entry);
    }

    pub fn appendSlice(self: *Self, entries: []const KeyShareEntry) mem.Allocator.Error!void {
        try self.shares.appendSlice(entries);
    }

    /// get encoded bytes size
    pub fn getEncLen(self: *const Self) usize {
        var len: usize = 0;
        len += @sizeOf(u16);
        for (self.shares.items) |*share| {
            len += @sizeOf(NamedGroup); // share group field
            len += @sizeOf(u16); // share length field
            len += share.key_exchange.items.len;
        }
        return len;
    }

    /// encode self to writer
    pub fn encode(self: *const Self, writer: anytype) @TypeOf(writer).Error!void {
        var length: usize = 0;
        for (self.shares.items) |*share| {
            length += @sizeOf(u16) * 2;
            length += share.key_exchange.items.len;
        }
        try writer.writeIntBig(u16, @intCast(u16, length));

        for (self.shares.items) |*share| {
            try writer.writeIntBig(u16, @enumToInt(share.group));
            try writer.writeIntBig(u16, @intCast(u16, self.shares.items.len));
            _ = try writer.write(share.key_exchange.items);
        }
    }
};

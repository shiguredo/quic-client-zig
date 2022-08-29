const std = @import("std");
const NamedGroup = @import("../extension.zig").NamedGroup;

pub const SupportedGroups = struct {
    const NamedGroupList = std.BoundedArray(NamedGroup, 65536 / @sizeOf(NamedGroup));

    named_group_list: NamedGroupList,

    const Self = @This();

    pub fn init() Self {
        var list = NamedGroupList.init(0) catch unreachable;
        return Self{
            .named_group_list = list,
        };
    }

    pub fn append(self: *Self, group: NamedGroup) error{Overflow}!void {
        try self.named_group_list.append(group);
    }

    pub fn appendSlice(self: *Self, groups: []const NamedGroup) error{Overflow}!void {
        try self.named_group_list.appendSlice(groups);
    }

    /// get encoded bytes size
    pub fn getEncLen(self: *const Self) usize {
        var len: usize = 0;
        len += @sizeOf(u16); // length field
        len += @sizeOf(NamedGroup) * self.named_group_list.len;
        return len;
    }

    /// encode self to to writer
    pub fn encode(self: *const Self, writer: anytype) @TypeOf(writer).Error!void {
        const slice = self.named_group_list.constSlice();

        try writer.writeIntBig(u16, @intCast(u16, slice.len * 2));
        for (slice) |group| {
            try writer.writeIntBig(u16, @enumToInt(group));
        }
    }
};

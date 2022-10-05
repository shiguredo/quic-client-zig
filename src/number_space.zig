const std = @import("std");
const enums = std.enums;
const mem = std.mem;
const RangeSet = @import("range_set.zig").RangeSet;

/// defined here https://www.rfc-editor.org/rfc/rfc9000.html#packet-numbers
pub const SpacesEnum = enum {
    initial,
    handshake,
    application,
};

pub const Spaces = struct {
    s: Earray,

    const Self = @This();
    const Earray = enums.EnumArray(SpacesEnum, NumberSpace);

    pub fn init(allocator: mem.Allocator) Self {
        var instance = Self{ .s = Earray.initUndefined() };
        var iter = instance.s.iterator();
        while (iter.next()) |*item| {
            item.value.* = NumberSpace.init(allocator);
        }
        return instance;
    }

    pub fn deinit(self: *Self) void {
        var iter = self.s.iterator();
        while (iter.next()) |*entry| {
            var item = entry.value;
            item.deinit();
        }
    }
};

pub const NumberSpace = struct {
    ack_ranges: RangeSet,
    current_number: u64 = 0,

    const Self = @This();

    pub fn init(allocator: mem.Allocator) Self {
        return .{
            .ack_ranges = RangeSet.init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.ack_ranges.deinit();
    }

    pub fn generate(self: *Self) u64 {
        defer self.current_number += 1;
        return self.current_number;
    }
};

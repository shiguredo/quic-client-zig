const std = @import("std");
const allocator = std.heap.page_allocator;

pub const Buffer = struct {
    array: []u8,
    offset: u32,
    size: u32,

    const Self = @This();

    pub fn init(size: u32) !Self {
        const array = try allocator.alloc(u8, size);
        const new_buffer: Self = .{
            .array = array,
            .offset = 0,
            .size = size,
        };
        return new_buffer;
    }

    pub fn deinit(self: *Self) void {
        self.offset = 0;
        self.size = 0;
        allocator.free(self.array);
    }
};

test "buffer test" {
    var buf = try Buffer.init(1 << 10);
    defer buf.deinit();

    var buf2 = try Buffer.init(1 << 20);
    defer buf2.deinit();
}

const std = @import("std");
const testing = std.testing;
const allocator = std.heap.page_allocator;

pub const BufferError = error {
    OutOfRangeError,
};

pub const Buffer = struct {
    array: []u8,
    offset: usize,
    size: usize,

    const Self = @This();

    pub fn init(size: usize) !Self {
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

    pub fn getSlice(self: *Self) []u8 {
        return self.array;
    }

    pub fn getOffsetSlice(self: *Self, offset: usize) BufferError![]u8 {
        const total_offset = self.offset + offset;
        if (total_offset < 0 or total_offset >= self.size) return BufferError.OutOfRangeError;

        return self.array[total_offset..];
    }
};

test "buffer test" {
    var buf = try Buffer.init(1 << 10);
    defer buf.deinit();

    var buf2 = try Buffer.init(1 << 20);
    defer buf2.deinit();
}

test "get offset slice" {
    var buf = try Buffer.init(1 << 16);
    defer buf.deinit();

    try testing.expectError(BufferError.OutOfRangeError, buf.getOffsetSlice(1<<20));
}
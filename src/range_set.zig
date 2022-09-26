const std = @import("std");
const mem = std.mem;
const math = std.math;
const testing = std.testing;

/// left-closed, right-open interval. [start, end)
/// which means the interval that includes its start, and
/// does not include its end.
pub const Range = struct {
    start: u64,
    end: u64,

    const Self = @This();

    const Error = error{NotMergeable};

    pub fn from(start: u64, end: u64) Self {
        std.debug.assert(start < end);
        return Self{
            .start = start,
            .end = end,
        };
    }

    /// check n is in range of "self"
    pub fn contain(self: Self, n: u64) bool {
        return self.start <= n and n < self.end;
    }

    /// check if self and another has common part or
    /// self touches another
    pub fn isMergeable(self: Self, another: Self) bool {
        const check =
            self.contain(another.start) or
            (self.end == another.start) or
            self.contain(another.end) or
            self.isSubsetOf(another) or
            another.isSubsetOf(self);
        return check;
    }

    pub fn merge(self: Self, another: Self) Error!Self {
        if (!self.isMergeable(another))
            return Error.NotMergeable;

        return Self.from(
            math.min(self.start, another.start),
            math.max(self.end, another.end),
        );
    }

    /// check if "self" is a subset of "r"
    pub fn isSubsetOf(self: Self, r: Self) bool {
        return r.start <= self.start and self.end <= r.end;
    }
};

test "Range -- isMergeable()" {
    var r1 = Range.from(100, 200);
    var r2 = Range.from(120, 300);
    var r3 = Range.from(130, 180);
    var r4 = Range.from(200, 230);
    var r5 = Range.from(110, 200);
    var r6 = Range.from(100, 300);
    var r7 = Range.from(250, 800);
    try testing.expect(r1.isMergeable(r2));
    try testing.expect(r2.isMergeable(r1));
    try testing.expect(r1.isMergeable(r3));
    try testing.expect(r3.isMergeable(r1));
    try testing.expect(r1.isMergeable(r4));
    try testing.expect(r4.isMergeable(r1));
    try testing.expect(r1.isMergeable(r5));
    try testing.expect(r5.isMergeable(r1));
    try testing.expect(r1.isMergeable(r6));
    try testing.expect(r6.isMergeable(r1));
    try testing.expect(!r1.isMergeable(r7));
    try testing.expect(!r7.isMergeable(r1));
}

test "Range -- merge()" {
    var r1 = Range.from(100, 200);
    var r2 = Range.from(120, 300);
    var r3 = Range.from(130, 180);
    var r4 = Range.from(200, 230);
    var r5 = Range.from(110, 200);
    var r6 = Range.from(100, 300);
    var r7 = Range.from(250, 800);
    try testing.expectEqual(Range.from(100, 300), try r1.merge(r2));
    try testing.expectEqual(Range.from(100, 300), try r2.merge(r1));
    try testing.expectEqual(Range.from(100, 200), try r1.merge(r3));
    try testing.expectEqual(Range.from(100, 200), try r3.merge(r1));
    try testing.expectEqual(Range.from(100, 230), try r1.merge(r4));
    try testing.expectEqual(Range.from(100, 230), try r4.merge(r1));
    try testing.expectEqual(Range.from(100, 200), try r1.merge(r5));
    try testing.expectEqual(Range.from(100, 200), try r5.merge(r1));
    try testing.expectEqual(Range.from(100, 300), try r1.merge(r6));
    try testing.expectEqual(Range.from(100, 300), try r6.merge(r1));
    try testing.expectError(error.NotMergeable, r1.merge(r7));
    try testing.expectError(error.NotMergeable, r7.merge(r1));
}

/// A set of Ranges
pub const RangeSet = struct {
    const Ranges = std.ArrayList(Range);

    /// ensured that these ranges has no common part and arranged in ascending order.
    ranges: Ranges,

    const Self = @This();

    pub fn init(allocator: mem.Allocator) Self {
        return .{
            .ranges = Ranges.init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.ranges.deinit();
    }

    pub fn add(self: *Self, range: Range) mem.Allocator.Error!void {
        var new_range = range;
        var merge_count: usize = 0;
        var merge_start: ?usize = null;
        var loop_break: ?usize = null;

        for (self.ranges.items) |r, i| {
            if (new_range.end < r.start) {
                loop_break = i;
                break;
            }

            if (new_range.merge(r)) |nr| {
                new_range = nr;
                merge_count += 1;
                if (merge_start == null) merge_start = i;
                continue;
            } else |_| {}
        }

        if (merge_start) |s| {
            // if some ranges are merged
            self.ranges.items[s] = new_range;

            if (merge_count > 1)
                self.removeN(s + 1, merge_count - 1);
        } else {
            // if no ranges are merged
            if (loop_break) |i| {
                try self.ranges.insert(i, new_range);
            } else {
                try self.ranges.append(new_range);
            }
        }
    }

    pub fn addOne(self: *Self, val: u64) mem.Allocator.Error!void {
        const r = Range.from(val, val + 1);
        try self.add(r);
    }

    pub fn start(self: Self) ?u64 {
        if (self.ranges.items.len > 0)
            return self.ranges.items[0].start
        else
            return null;
    }

    pub fn end(self: Self) ?u64 {
        const len = self.ranges.items.len;
        if (len > 0)
            return self.ranges.items[len - 1].end
        else
            return null;
    }

    pub fn include(self: Self, r: Range) bool {
        for (self.ranges.items) |item| {
            if (r.isSubsetOf(item))
                return true;
        }
        return false;
    }

    // struct-local functions
    /// remove N elements from idx
    fn removeN(self: *Self, idx: usize, n: usize) void {
        const new_len = self.ranges.items.len - n;
        for (self.ranges.items[idx..new_len]) |*p, i| {
            p.* = self.ranges.items[idx + i + n];
        }
        self.ranges.items.len = new_len;
        return;
    }
};

test "RangeSet -- add" {
    const range_array = [_]Range{
        Range.from(100, 200),
        Range.from(180, 300),
        Range.from(50, 60),
        Range.from(400, 500),
    };

    var range_set = RangeSet.init(testing.allocator);
    defer range_set.deinit();

    for (range_array) |r| {
        try range_set.add(r);
    }

    try testing.expectEqualSlices(
        Range,
        &[_]Range{
            Range.from(50, 60),
            Range.from(100, 300),
            Range.from(400, 500),
        },
        range_set.ranges.items,
    );

    var r = Range.from(30, 40);
    try range_set.add(r);
    try testing.expectEqualSlices(
        Range,
        &[_]Range{
            Range.from(30, 40),
            Range.from(50, 60),
            Range.from(100, 300),
            Range.from(400, 500),
        },
        range_set.ranges.items,
    );

    r = Range.from(40, 50);
    try range_set.add(r);
    try testing.expectEqualSlices(
        Range,
        &[_]Range{
            Range.from(30, 60),
            Range.from(100, 300),
            Range.from(400, 500),
        },
        range_set.ranges.items,
    );

    r = Range.from(40, 50);
    try range_set.add(r);
    try testing.expectEqualSlices(
        Range,
        &[_]Range{
            Range.from(30, 60),
            Range.from(100, 300),
            Range.from(400, 500),
        },
        range_set.ranges.items,
    );

    r = Range.from(50, 110);
    try range_set.add(r);
    try testing.expectEqualSlices(
        Range,
        &[_]Range{
            Range.from(30, 300),
            Range.from(400, 500),
        },
        range_set.ranges.items,
    );

    r = Range.from(20, 600);
    try range_set.add(r);
    try testing.expectEqualSlices(
        Range,
        &[_]Range{
            Range.from(20, 600),
        },
        range_set.ranges.items,
    );
}

test "RangeSet -- isSubsetOf" {
    const range_array = [_]Range{
        Range.from(100, 200),
        Range.from(180, 300),
        Range.from(50, 60),
        Range.from(400, 500),
    };

    var range_set = RangeSet.init(testing.allocator);
    defer range_set.deinit();

    for (range_array) |r| {
        try range_set.add(r);
    }
    // range_set should be
    // [50, 60), [100, 300), [400, 500)
    // from the previous test

    try testing.expect(range_set.include(Range.from(200, 250)));
    try testing.expect(range_set.include(Range.from(100, 250)));
    try testing.expect(range_set.include(Range.from(200, 300)));
    try testing.expect(range_set.include(Range.from(100, 300)));

    try testing.expect(!range_set.include(Range.from(70, 80)));
    try testing.expect(!range_set.include(Range.from(50, 80)));
    try testing.expect(!range_set.include(Range.from(40, 55)));
    try testing.expect(!range_set.include(Range.from(40, 70)));
    try testing.expect(!range_set.include(Range.from(40, 700)));
    try testing.expect(!range_set.include(Range.from(60, 70)));
    try testing.expect(!range_set.include(Range.from(40, 50)));
}

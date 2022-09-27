const std = @import("std");
const mem = std.mem;
const io = std.io;
const testing = std.testing;
const enums = std.enums;

const extension = @import("extension.zig");

const ClientHello = @import("client_server_hello.zig").ClientHello;
const ServerHello = @import("client_server_hello.zig").ServerHello;

pub const HandshakeType = enum(u8) {
    client_hello = 0x01,
    server_hello = 0x02,

    const Self = @This();

    pub fn cast(value: u8) error{EnumCastFailed}!Self {
        return switch (value) {
            0x01...0x02 => @intToEnum(Self, value),
            else => return error.EnumCastFailed,
        };
    }
};

/// decoded Handshake
/// https://www.rfc-editor.org/rfc/rfc8446#section-4
pub const Handshake = union(HandshakeType) {
    client_hello: ClientHello,
    server_hello: ServerHello,

    const Self = @This();

    const Content = union(HandshakeType) {
        client_hello: ClientHello,
        server_hello: ServerHello,
    };

    pub fn initClient(allocator: mem.Allocator) !Self {
        var instance = Self{
            .client_hello = try ClientHello.init(allocator),
        };
        return instance;
    }

    pub fn deinit(self: Self) void {
        switch (self) {
            .client_hello => |h| h.deinit(),
            .server_hello => |h| h.deinit(),
        }
    }

    pub fn getEncLen(self: *const Self) usize {
        var len: usize = blk: {
            comptime var temp = 0;
            temp += @sizeOf(HandshakeType);
            temp += @bitSizeOf(u24) / 8; // length field
            break :blk temp;
        };
        len += switch (self.*) {
            .client_hello => |*h| h.getEncLen(),
            .server_hello => 0, // TODO: implement for server hello
        };

        return len;
    }

    /// encode self to writer
    /// implemented only for .{.client_hello} now.
    pub fn encode(self: *const Self, writer: anytype) !void {
        const msg_type = @enumToInt(@as(HandshakeType, self.*));
        try writer.writeIntBig(u8, msg_type);

        const length = switch (self.*) {
            .client_hello => |*c_hello| c_hello.getEncLen(),
            else => 0, // TODO: inmplement for server hello
        };
        try writer.writeIntBig(u24, @intCast(u24, length));

        switch (self.*) {
            .client_hello => |c_hello| try c_hello.encode(writer),
            .server_hello => {}, // TODO: inmplement for server hello
        }

        return;
    }

    pub fn decode(reader: anytype, allocator: mem.Allocator) !Self {
        const handshake_type = try HandshakeType.cast(try reader.readIntBig(u8));

        const length = try reader.readIntBig(u24);
        var stream = io.limitedReader(reader, @intCast(u64, length));
        var s_reader = stream.reader();

        return switch (handshake_type) {
            .server_hello => s_h: {
                const s_hello = try ServerHello.decode(s_reader, allocator);
                break :s_h Self{ .server_hello = s_hello };
            },
            else => unreachable, // TODO: implement for other handshake types
        };
    }
};

/// raw byte data of struct Handshake
/// https://www.rfc-editor.org/rfc/rfc8446#section-4
pub const HandshakeRaw = struct {
    data: std.ArrayList(u8),
    max_len: usize,

    const Self = @This();

    pub fn init(allocator: mem.Allocator, max_len: usize) !Self {
        return .{
            .data = try std.ArrayList(u8).initCapacity(
                allocator,
                max_len,
            ),
            .max_len = max_len,
        };
    }

    pub fn fromArrayList(data: std.ArrayList(u8)) Self {
        return .{
            .data = data,
            .max_len = data.items.len,
        };
    }

    pub fn deinit(self: Self) void {
        self.data.deinit();
    }

    pub fn isComplete(self: Self) bool {
        return self.max_len == self.data.items.len;
    }

    pub fn write(self: *Self, buf: []const u8) !usize {
        const len = self.max_len - self.data.items.len;
        try self.data.appendSlice(buf[0..len]);
        return len;
    }
};

test "encode client hello" {
    const Buffer = @import("../buffer.zig").Buffer;

    var client_hello = try ClientHello.init(testing.allocator);
    try client_hello.appendCipher([_]u8{ 0x13, 0x01 }); // TLS_AES_128_GCM_SHA256
    var extensions = [_]extension.Extension{
        supported_groups: {
            var sg = extension.SupportedGroups.init();
            try sg.append(.x25519);
            break :supported_groups extension.Extension{ .supported_groups = sg };
        },
        signature_algorithms: {
            var sa = extension.SignatureAlgorithms.init();
            try sa.appendSlice(&[_]extension.SignatureScheme{
                .ecdsa_secp256r1_sha256,
                .rsa_pss_rsae_sha256,
                .rsa_pksc1_sha256,
            });
            break :signature_algorithms extension.Extension{ .signature_algorithms = sa };
        },
        supported_versions: {
            var sv = extension.SupportedVersions.init(.client_hello);
            try sv.append(extension.SupportedVersions.TLS13);
            break :supported_versions extension.Extension{ .supported_versions = sv };
        },
        key_share: {
            var ks = extension.KeyShare.init(.client_hello, testing.allocator);
            break :key_share extension.Extension{ .key_share = ks };
        },
    };
    try client_hello.appendExtensionSlice(&extensions);

    var client_hello_hs = Handshake{ .client_hello = client_hello };
    defer client_hello_hs.deinit();

    var buf = Buffer(1024).init();
    try client_hello_hs.encode(buf.writer());
    const len = buf.unreadLength();
    const before_random = buf.getUnreadSlice()[0..6];
    const after_random = buf.getUnreadSlice()[6 + 32 .. len];
    try testing.expectEqual(@as(u8, 0x01), buf.getUnreadSlice()[0]); // handshake type "ClientHello"
    try testing.expectEqual(len - 4, @intCast(usize, mem.readInt(u24, before_random[1..4], .Big))); // length field of handshake
    try testing.expectEqual(@as(u16, 0x0303), mem.readInt(u16, before_random[4..6], .Big)); // legacy_version == 0x0303

    // zig fmt: off
        try testing.expectFmt(
            "00" ++ // legacy_session_id
            "00021301" ++ // cipher_suites
            "0100" ++ // legacy_compression_id
            "0021" ++ // extension field length
            "000A00040002001D" ++ // supported_groups
            "000D00080006040308040401" ++ // sigunature_algorithms
            "002B0003020304" ++ // supported_versions
            "003300020000", // key_share
            "{s}",
            .{std.fmt.fmtSliceHexUpper(after_random)},
        );
        // zig fmt: on

    try testing.expectEqual(len, client_hello_hs.getEncLen());
}

test "decode server hello" {
    var server_hello_bytes: [90]u8 = undefined;
    // zig fmt: off
    _ = try std.fmt.hexToBytes(
        &server_hello_bytes,
        "0200005603034e1f7043fa33e9d7d35e" ++
        "e9d31701bd8a4650aa79b40dc7c1a8aa" ++
        "4a35fa0a244a00130100002e002b0002" ++
        "030400330024001d00207eac8ab90153" ++
        "83235c836907686979a8f29200728cea" ++
        "2b7d9952d75039974850",
    );
    // zig fmt: on
    var stream = std.io.fixedBufferStream(&server_hello_bytes);
    const s_hello = try Handshake.decode(stream.reader(), testing.allocator);
    defer s_hello.deinit();

    try testing.expectEqual(
        HandshakeType.server_hello,
        @as(HandshakeType, s_hello),
    );

    switch (s_hello) {
        .server_hello => |s_hello| {
            try testing.expectFmt(
                "4e1f7043fa33e9d7d35ee9d31701bd8a" ++ "4650aa79b40dc7c1a8aa4a35fa0a244a",
                "{x}",
                .{std.fmt.fmtSliceHexLower(&s_hello.random_bytes)},
            );
            try testing.expectEqualSlices(
                u8,
                &[_]u8{ 0x13, 0x01 },
                &s_hello.cipher_suite,
            );
        },
        else => unreachable,
    }
}

const std = @import("std");
const crypto = std.crypto;
const io = std.io;
const mem = std.mem;
const testing = std.testing;

const q_crypto = @import("crypto.zig");
const util = @import("util.zig");
const Buffer = @import("buffer.zig").Buffer;
const BufferError = @import("buffer.zig").BufferError;

const Hmac = q_crypto.Hmac;
const Hkdf = q_crypto.Hkdf;

pub const Provider = struct {
    initial_secret: [Hmac.key_length]u8 = undefined,
    client_initial: [Hmac.key_length]u8 = undefined,
    server_initial: [Hmac.key_length]u8 = undefined,
    client_initial_key: [QUIC_KEY_LENGTH]u8 = undefined,
    server_initial_key: [QUIC_KEY_LENGTH]u8 = undefined,
    client_iv: [QUIC_IV_LENGTH]u8 = undefined,
    server_iv: [QUIC_IV_LENGTH]u8 = undefined,
    client_hp: [QUIC_HP_KEY_LENGTH]u8 = undefined,
    server_hp: [QUIC_HP_KEY_LENGTH]u8 = undefined,

    const Self = @This();

    const QUIC_KEY_LENGTH = 16;
    const QUIC_IV_LENGTH = 12;
    const QUIC_HP_KEY_LENGTH = 16;

    /// derives initial secret from client's destination connection ID
    /// and set it to self.initial_secret
    pub fn setUpInitial(self: *Self, key: []const u8) void {
        const initial_secret = Hkdf.extract(&q_crypto.INITIAL_SALT_V1, key);
        self.initial_secret = initial_secret;

        q_crypto.hkdfExpandLabel(&self.client_initial, initial_secret, "client in", "");
        q_crypto.hkdfExpandLabel(&self.server_initial, initial_secret, "server in", "");

        q_crypto.hkdfExpandLabel(&self.client_initial_key, self.client_initial, "quic key", "");
        q_crypto.hkdfExpandLabel(&self.server_initial_key, self.server_initial, "quic key", "");

        q_crypto.hkdfExpandLabel(&self.client_iv, self.client_initial, "quic iv", "");
        q_crypto.hkdfExpandLabel(&self.server_iv, self.server_initial, "quic iv", "");

        q_crypto.hkdfExpandLabel(&self.client_hp, self.client_initial, "quic hp", "");
        q_crypto.hkdfExpandLabel(&self.server_hp, self.server_initial, "quic hp", "");
    }
};

pub const TlsMessageType = enum {
    handshake,
};

pub const TlsMessage = struct {
    handshake: Handshake,

    const Self = @This();

    pub fn getEncLen(self: *const Self) usize {
        return switch (self.*) {
            .handshake => |*m| m.getEncLen(),
        };
    }

    pub fn encode(self: *const Self, buf_ptr: anytype) BufferError!void {
        return switch (self.*) {
            .handshake => |*m| m.encode(buf_ptr),
        };
    }
};

pub const HandshakeType = enum(u8) {
    client_hello = 0x01,
    server_hello = 0x02,
};

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

    pub fn deinit(self: *Self) void {
        switch (self.*) {
            .client_hello => |*h| h.deinit(),
            .server_hello => {},
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

    /// implemented only for .{.client_hello} .
    pub fn encode(self: *const Self, buf_ptr: anytype) BufferError!void {
        const msg_type = @enumToInt(@as(HandshakeType, self.*));
        try buf_ptr.writer().writeIntBig(u8, msg_type);

        const length = switch (self.*) {
            .client_hello => |*c_hello| c_hello.getEncLen(),
            else => 0 // TODO: inmplement for server hello
        };
        try buf_ptr.writer().writeIntBig(u24, @intCast(u24, length));

        switch (self.*) {
            .client_hello => |c_hello| try c_hello.encode(buf_ptr),
            .server_hello => {}, // TODO: inmplement for server hello
        }

        return;
    }
};

/// TLS 1.3 ClientHello
pub const ClientHello = struct {
    const LEGACY_VERSION: u16 = 0x0303;
    const RANDOM_FIELD_LEN = 32;
    const SessionId = std.BoundedArray(u8, 32);
    const CipherSuites = std.BoundedArray([2]u8, 65536 / @sizeOf([2]u8));
    const CompressionMethods = std.BoundedArray(u8, 256);
    const Extensions = std.ArrayList(extension.Extension);

    random_bytes: [32]u8,
    legacy_session_id: SessionId,
    cipher_suites: CipherSuites,
    legacy_compression_methods: CompressionMethods,
    extensions: Extensions,

    const Self = @This();

    pub fn init(allocator: mem.Allocator) !Self {
        var instance = Self{
            .random_bytes = undefined,
            .legacy_session_id = try SessionId.init(0),
            .cipher_suites = try CipherSuites.init(0),
            .legacy_compression_methods = try CompressionMethods.init(0),
            .extensions = Extensions.init(allocator),
        };

        crypto.random.bytes(&instance.random_bytes); // assign random bytes
        try instance.cipher_suites.appendSlice(&[_][2]u8{.{ 0x13, 0x01 }}); // supports TLS_AES_128_GCM_SHA256
        try instance.legacy_compression_methods.appendSlice(&[_]u8{0}); // value for "null"

        const extensions = [_]extension.Extension{
            .{ .supported_groups = try extension.SupportedGroups.init() },
            .{ .signature_algorithms = try extension.SignatureAlgorithms.init() },
            .{ .supported_versions = extension.SupportedVersions.init() },
            .{ .key_share = try extension.KeyShare.init(allocator) },
        };

        try instance.extensions.appendSlice(&extensions);

        return instance;
    }

    pub fn deinit(self: *Self) void {
        for (self.extensions.items) |*ext| {
            ext.deinit();
        }
        self.extensions.deinit();
    }

    /// get encoded bytes size
    pub fn getEncLen(self: *const Self) usize {
        var len: usize = blk: {
            comptime var temp = 0;
            temp += @sizeOf(u16); // legacy version field
            temp += RANDOM_FIELD_LEN;
            break :blk temp;
        };

        len += @sizeOf(u8); // session id's length field
        len += @sizeOf(u8) * self.legacy_session_id.len;

        len += @sizeOf(u16); // cipher suites' length field
        len += @sizeOf([2]u8) * self.cipher_suites.len;

        len += @sizeOf(u8); // commpression methods' length field
        len += @sizeOf(u8) * self.legacy_compression_methods.len;

        len += @sizeOf(u16); // extension length field
        for (self.extensions.items) |*ext| {
            len += ext.getEncLen();
        }

        return len;
    }

    /// writes to buffer and returns write count
    pub fn encode(self: *const Self, buf_ptr: anytype) BufferError!void {
        // legacy_version
        try buf_ptr.writer().writeIntBig(u16, LEGACY_VERSION);

        // ramdom
        _ = try buf_ptr.writer().write(&self.random_bytes);

        // legacy_session_id
        try buf_ptr.writer().writeIntBig(u8, @intCast(u8, self.legacy_session_id.len));
        _ = try buf_ptr.writer().write(self.legacy_session_id.constSlice());

        // cipher_suites
        const suites_byte_ptr = mem.sliceAsBytes(self.cipher_suites.constSlice());
        try buf_ptr.writer().writeIntBig(u16, @intCast(u16, suites_byte_ptr.len));
        _ = try buf_ptr.writer().write(suites_byte_ptr);

        // legacy_compression_methods
        try buf_ptr.writer().writeIntBig(u8, @intCast(u8, self.legacy_compression_methods.len));
        _ = try buf_ptr.writer().write(self.legacy_compression_methods.constSlice());

        // extensions
        var ext_total_len: usize = 0;
        for (self.extensions.items) |*ext| ext_total_len += ext.getEncLen();
        try buf_ptr.writer().writeIntBig(u16, @intCast(u16, ext_total_len));

        for (self.extensions.items) |*ext| try ext.encode(buf_ptr);

        return;
    }
};

pub const ServerHello = struct {};

/// TLS message extensions.
/// see https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2
pub const extension = struct {
    pub const ExtensionType = enum(u16) {
        supported_groups = 10,
        signature_algorithms = 13,
        supported_versions = 43,
        key_share = 51,
    };

    pub const Extension = union(ExtensionType) {
        supported_groups: SupportedGroups,
        signature_algorithms: SignatureAlgorithms,
        supported_versions: SupportedVersions,
        key_share: KeyShare,

        const Self = @This();

        pub fn deinit(self: *Self) void {
            switch (self.*) {
                .key_share => |*e| e.deinit(),
                else => {},
            }
        }

        /// get encoded byte size
        pub fn getEncLen(self: *const Self) usize {
            var len: usize = 0;
            len += @sizeOf(ExtensionType);
            len += @sizeOf(u16); // content length field
            len += switch (self.*) {
                .supported_groups => |e| e.getEncLen(),
                .signature_algorithms => |e| e.getEncLen(),
                .supported_versions => |e| e.getEncLen(),
                .key_share => |e| e.getEncLen(),
            };
            return len;
        }

        /// writes to buffer and returns write count
        pub fn encode(self: *const Self, buf_ptr: anytype) BufferError!void {
            const ext_type = @as(ExtensionType, self.*);
            try buf_ptr.writer().writeIntBig(u16, @enumToInt(ext_type));

            const data_len = switch (self.*) {
                .supported_groups => |e| e.getEncLen(),
                .signature_algorithms => |e| e.getEncLen(),
                .supported_versions => |e| e.getEncLen(),
                .key_share => |e| e.getEncLen(),
            };
            try buf_ptr.writer().writeIntBig(u16, @intCast(u16, data_len));

            try switch (self.*) {
                .supported_groups => |e| e.encode(buf_ptr),
                .signature_algorithms => |e| e.encode(buf_ptr),
                .supported_versions => |e| e.encode(buf_ptr),
                .key_share => |e| e.encode(buf_ptr),
            };
        }
    };

    pub const NamedGroup = enum(u16) {
        // Elliptic Curve Groups (ECDHE)
        secp256r1 = 0x0017,
        secp384r1 = 0x0018,
        secp521r1 = 0x0019,
        x25519 = 0x001D,
        x448 = 0x001E,

        // Finite Field Groups (DHE)
        ffdhe2048 = 0x0100,
        ffdhe3072 = 0x0101,
        ffdhe4096 = 0x0102,
        ffdhe6144 = 0x0103,
        ffdhe8192 = 0x0104,

        // Reserved Code Points
        ffdhe_private_use,
        ecdhe_private_use,
    };

    pub const SignatureScheme = enum(u16) {
        // RSASSA-PKCS1-v1_5 algorithms
        rsa_pksc1_sha256 = 0x0401,
        rsa_pksc1_sha384 = 0x0501,
        rsa_pksc1_sha512 = 0x0601,

        // ECDSA algorithms
        ecdsa_secp256r1_sha256 = 0x0403,
        ecdsa_secp384r1_sha384 = 0x0503,
        ecdsa_secp512r1_sha512 = 0x0603,

        // RSASSA-PSS algorithms with public key OID rsaEncryption
        rsa_pss_rsae_sha256 = 0x0804,
        rsa_pss_rsae_sha384 = 0x0805,
        rsa_pss_rsae_sha512 = 0x0806,

        // EdDSA algorithms
        ed25519 = 0x0807,
        ed448 = 0x0808,

        // RSASSA-PSS algorithms with public key OID RSASSA-PSS
        rsa_pss_pss_sha256 = 0x0809,
        rsa_pss_pss_sha384 = 0x080a,
        rsa_pss_pss_sha512 = 0x080b,

        // Legacy algorithms
        rsa_pkcs1_sha1 = 0x0201,
        ecdsa_sha1 = 0x0203,

        // Reserved Code Points
        private_use,
    };

    pub const SupportedGroups = struct {
        const NamedGroupList = std.BoundedArray(NamedGroup, 65536 / @sizeOf(NamedGroup));

        named_group_list: NamedGroupList,

        const Self = @This();

        pub fn init() !Self {
            var list = try NamedGroupList.init(0);
            try list.append(.x25519);
            return Self{
                .named_group_list = list,
            };
        }

        /// get encoded bytes size
        pub fn getEncLen(self: *const Self) usize {
            var len: usize = 0;
            len += @sizeOf(u16); // length field
            len += @sizeOf(NamedGroup) * self.named_group_list.len;
            return len;
        }

        pub fn encode(self: *const Self, buf_ptr: anytype) BufferError!void {
            const slice = self.named_group_list.constSlice();

            try buf_ptr.writer().writeIntBig(u16, @intCast(u16, slice.len * 2));
            for (slice) |group| {
                try buf_ptr.writer().writeIntBig(u16, @enumToInt(group));
            }
        }
    };

    pub const SignatureAlgorithms = struct {
        const Algorithms = std.BoundedArray(SignatureScheme, 65536 / @sizeOf(SignatureScheme));
        supported_algorithms: Algorithms,

        const Self = @This();

        pub fn init() !Self {
            var supports = try Algorithms.init(0);
            try supports.append(.ecdsa_secp256r1_sha256);
            try supports.append(.rsa_pss_rsae_sha256);
            try supports.append(.rsa_pksc1_sha256);
            return Self{
                .supported_algorithms = supports,
            };
        }

        /// get encoded bytes size
        pub fn getEncLen(self: *const Self) usize {
            var len: usize = 0;
            len += @sizeOf(u16); // length field
            len += @sizeOf(SignatureScheme) * self.supported_algorithms.len;
            return len;
        }

        pub fn encode(self: *const Self, buf_ptr: anytype) BufferError!void {
            const slice = self.supported_algorithms.constSlice();

            try buf_ptr.writer().writeIntBig(u16, @intCast(u16, slice.len * @sizeOf(u16)));
            for (slice) |algo| {
                try buf_ptr.writer().writeIntBig(u16, @enumToInt(algo));
            }
        }
    };

    /// only tls 1.3 is supported
    pub const SupportedVersions = struct {
        pub const TLS13 = 0x0304;
        const Self = @This();

        pub fn init() Self {
            return .{};
        }

        /// get encoded bytes size
        pub fn getEncLen(self: *const Self) usize {
            _ = self;
            return blk: {
                comptime var temp = 0;
                temp += @sizeOf(u8);
                temp += @sizeOf(u16) * 1;
                break :blk temp;
            };
        }

        /// buf must be the return type of Buffer(capacity) in buffer.zig
        pub fn encode(self: *const Self, buf_ptr: anytype) BufferError!void {
            _ = self;
            try buf_ptr.writer().writeIntBig(u8, @as(u8, @sizeOf(u16)));
            try buf_ptr.writer().writeIntBig(u16, @as(u16, TLS13));
        }
    };

    /// KeyShareClientHello
    pub const KeyShare = struct {
        const Shares = std.ArrayList(KeyShareEntry);

        shares: Shares,

        const Self = @This();

        pub const KeyShareEntry = struct {
            group: NamedGroup,
            key_exchange: std.ArrayList(u8),
        };

        pub fn init(allocator: mem.Allocator) !Self {
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

        /// buf must be the return type of Buffer(capacity) in buffer.zig
        pub fn encode(self: *const Self, buf_ptr: anytype) BufferError!void {
            var length: usize = 0;
            for (self.shares.items) |*share| {
                length += @sizeOf(u16) * 2;
                length += share.key_exchange.items.len;
            }
            try buf_ptr.writer().writeIntBig(u16, @intCast(u16, length));

            for (self.shares.items) |*share| {
                try buf_ptr.writer().writeIntBig(u16, @enumToInt(share.group));
                try buf_ptr.writer().writeIntBig(u16, @intCast(u16, self.shares.items.len));
                _ = try buf_ptr.writer().write(share.key_exchange.items);
            }
        }
    };

    test "Extension" {
        var buf = Buffer(1024).init();

        // supported groups
        var sg = Extension{ .supported_groups = try SupportedGroups.init() };
        defer sg.deinit();
        try sg.encode(&buf);
        try testing.expectFmt(
            "000A00040002001D",
            "{s}",
            .{std.fmt.fmtSliceHexUpper(buf.getUnreadSlice())},
        );
        try testing.expectEqual(buf.unreadLength(), sg.getEncLen());

        // signature algorithms
        buf.clear();
        var sa = Extension{ .signature_algorithms = try SignatureAlgorithms.init() };
        defer sa.deinit();
        try sa.encode(&buf);
        try testing.expectFmt(
            "000D00080006040308040401",
            "{s}",
            .{std.fmt.fmtSliceHexUpper(buf.getUnreadSlice())},
        );
        try testing.expectEqual(buf.unreadLength(), sa.getEncLen());

        // supported versions
        buf.clear();
        var sv = Extension{ .supported_versions = SupportedVersions.init() };
        defer sv.deinit();
        try sv.encode(&buf);
        try testing.expectFmt(
            "002B0003020304",
            "{s}",
            .{std.fmt.fmtSliceHexUpper(buf.getUnreadSlice())},
        );
        try testing.expectEqual(buf.unreadLength(), sv.getEncLen());

        // key share
        buf.clear();
        var ks = Extension{ .key_share = try KeyShare.init(testing.allocator) };
        defer ks.deinit();
        try ks.encode(&buf);
        try testing.expectFmt(
            "003300020000",
            "{s}",
            .{std.fmt.fmtSliceHexUpper(buf.getUnreadSlice())},
        );
        try testing.expectEqual(buf.unreadLength(), ks.getEncLen());
    }
};

test "client hello" {
    var client_hello = try Handshake.initClient(testing.allocator);
    defer client_hello.deinit();
    var buf = Buffer(1024).init();
    try client_hello.encode(&buf);
    const len = buf.unreadLength();
    const before_random = buf.getUnreadSlice()[0..6];
    const after_random = buf.getUnreadSlice()[6 + 32 .. len];
    try testing.expectEqual(@as(u8, 0x01), buf.getUnreadSlice()[0]); // handshake type "ClientHello"
    try testing.expectEqual(len - 4, @intCast(usize, mem.readInt(u24, before_random[1..4], .Big))); // length field of handshake
    try testing.expectEqual(@as(u16, 0x0303), mem.readInt(u16, before_random[4..6], .Big)); // legacy_version == 0x0303

    try testing.expectFmt(
        ("00" ++ // legacy_session_id
            "00021301" ++ // cipher_suites
            "0100" ++ // legacy_compression_id
            "0021" ++ // extension field length
            "000A00040002001D" ++ // supported_groups
            "000D00080006040308040401" ++ // sigunature_algorithms
            "002B0003020304" ++ // supported_versions
            "003300020000"), // key_share
        "{s}",
        .{std.fmt.fmtSliceHexUpper(after_random)},
    );

    try testing.expectEqual(len, client_hello.getEncLen());
}

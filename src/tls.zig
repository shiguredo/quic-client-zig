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

pub const QuicKeys = struct {
    secret: [Hmac.key_length]u8 = undefined,
    key: [QUIC_KEY_LENGTH]u8 = undefined,
    iv: [QUIC_IV_LENGTH]u8 = undefined,
    hp: [QUIC_HP_KEY_LENGTH]u8 = undefined,

    const QUIC_KEY_LENGTH = 16;
    const QUIC_IV_LENGTH = 12;
    const QUIC_HP_KEY_LENGTH = 16;
};

pub const Provider = struct {
    initial_secret: [Hmac.key_length]u8 = undefined,
    client_initial: ?QuicKeys = null,
    server_initial: ?QuicKeys = null,

    const Self = @This();

    const Error = error{KeyNotInstalled};

    /// derives initial secret from client's destination connection ID
    /// and set it to self.initial_secret
    pub fn setUpInitial(self: *Self, key: []const u8) void {
        const initial_secret = Hkdf.extract(&q_crypto.INITIAL_SALT_V1, key);
        self.initial_secret = initial_secret;
        var client_initial = QuicKeys{};
        var server_initial = QuicKeys{};

        q_crypto.hkdfExpandLabel(&client_initial.secret, initial_secret, "client in", "");
        q_crypto.hkdfExpandLabel(&server_initial.secret, initial_secret, "server in", "");

        q_crypto.hkdfExpandLabel(&client_initial.key, client_initial.secret, "quic key", "");
        q_crypto.hkdfExpandLabel(&server_initial.key, server_initial.secret, "quic key", "");

        q_crypto.hkdfExpandLabel(&client_initial.iv, client_initial.secret, "quic iv", "");
        q_crypto.hkdfExpandLabel(&server_initial.iv, server_initial.secret, "quic iv", "");

        q_crypto.hkdfExpandLabel(&client_initial.hp, client_initial.secret, "quic hp", "");
        q_crypto.hkdfExpandLabel(&server_initial.hp, server_initial.secret, "quic hp", "");

        self.client_initial = client_initial;
        self.server_initial = server_initial;
    }

    test "setUpInitial" {
        // test vectors from https://www.rfc-editor.org/rfc/rfc9001#name-sample-packet-protection
        var tls_provider = Provider{};
        tls_provider.setUpInitial(
            &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 },
        );

        const client_initial = tls_provider.client_initial.?;
        const server_initial = tls_provider.server_initial.?;

        // initial secret
        try testing.expectFmt(
            "7db5df06e7a69e432496adedb0085192" ++ "3595221596ae2ae9fb8115c1e9ed0a44",
            "{s}",
            .{std.fmt.fmtSliceHexLower(&tls_provider.initial_secret)},
        );

        // client initial secret
        try testing.expectFmt(
            "c00cf151ca5be075ed0ebfb5c80323c4" ++ "2d6b7db67881289af4008f1f6c357aea",
            "{s}",
            .{std.fmt.fmtSliceHexLower(&client_initial.secret)},
        );

        // client initial key
        try testing.expectFmt(
            "1f369613dd76d5467730efcbe3b1a22d",
            "{s}",
            .{std.fmt.fmtSliceHexLower(&client_initial.key)},
        );

        // client iv
        try testing.expectFmt(
            "fa044b2f42a3fd3b46fb255c",
            "{s}",
            .{std.fmt.fmtSliceHexLower(&client_initial.iv)},
        );

        // client hp key
        try testing.expectFmt(
            "9f50449e04a0e810283a1e9933adedd2",
            "{s}",
            .{std.fmt.fmtSliceHexLower(&client_initial.hp)},
        );

        // server initial secret
        try testing.expectFmt(
            "3c199828fd139efd216c155ad844cc81" ++ "fb82fa8d7446fa7d78be803acdda951b",
            "{s}",
            .{std.fmt.fmtSliceHexLower(&server_initial.secret)},
        );

        // server key
        try testing.expectFmt(
            "cf3a5331653c364c88f0f379b6067e37",
            "{s}",
            .{std.fmt.fmtSliceHexLower(&server_initial.key)},
        );

        // server iv
        try testing.expectFmt(
            "0ac1493ca1905853b0bba03e",
            "{s}",
            .{std.fmt.fmtSliceHexLower(&server_initial.iv)},
        );

        // server hp key
        try testing.expectFmt(
            "c206b8d9b9f0f37644430b490eeaa314",
            "{s}",
            .{std.fmt.fmtSliceHexLower(&server_initial.hp)},
        );
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

    /// encode self to writer
    pub fn encode(self: *const Self, writer: anytype) BufferError!void {
        return switch (self.*) {
            .handshake => |*m| m.encode(writer),
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

    /// encode self to writer
    /// implemented only for .{.client_hello} now.
    pub fn encode(self: *const Self, writer: anytype) BufferError!void {
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

    test "client hello" {
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
                var sv = extension.SupportedVersions.init();
                try sv.append(extension.SupportedVersions.TLS13);
                break :supported_versions extension.Extension{ .supported_versions = sv };
            },
            key_share: {
                var ks = extension.KeyShare.init(testing.allocator);
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
        try instance.legacy_compression_methods.appendSlice(&[_]u8{0}); // value for "null"

        return instance;
    }

    pub fn deinit(self: *Self) void {
        for (self.extensions.items) |*ext| {
            ext.deinit();
        }
        self.extensions.deinit();
    }

    pub fn appendCipher(self: *Self, cipher_suite: [2]u8) error{Overflow}!void {
        try self.cipher_suites.append(cipher_suite);
    }

    pub fn appendExtension(self: *Self, ext: extension.Extension) mem.Allocator.Error!void {
        try self.extensions.append(ext);
    }

    pub fn appendExtensionSlice(
        self: *Self,
        exts: []const extension.Extension,
    ) mem.Allocator.Error!void {
        try self.extensions.appendSlice(exts);
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

    /// encode self to writer
    pub fn encode(self: *const Self, writer: anytype) BufferError!void {
        // legacy_version
        try writer.writeIntBig(u16, LEGACY_VERSION);

        // ramdom
        _ = try writer.write(&self.random_bytes);

        // legacy_session_id
        try writer.writeIntBig(u8, @intCast(u8, self.legacy_session_id.len));
        _ = try writer.write(self.legacy_session_id.constSlice());

        // cipher_suites
        const suites_byte_ptr = mem.sliceAsBytes(self.cipher_suites.constSlice());
        try writer.writeIntBig(u16, @intCast(u16, suites_byte_ptr.len));
        _ = try writer.write(suites_byte_ptr);

        // legacy_compression_methods
        try writer.writeIntBig(u8, @intCast(u8, self.legacy_compression_methods.len));
        _ = try writer.write(self.legacy_compression_methods.constSlice());

        // extensions
        var ext_total_len: usize = 0;
        for (self.extensions.items) |*ext| ext_total_len += ext.getEncLen();
        try writer.writeIntBig(u16, @intCast(u16, ext_total_len));

        for (self.extensions.items) |*ext| try ext.encode(writer);

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

        /// encode self to writer
        pub fn encode(self: *const Self, writer: anytype) BufferError!void {
            const ext_type = @as(ExtensionType, self.*);
            try writer.writeIntBig(u16, @enumToInt(ext_type));

            const data_len = switch (self.*) {
                .supported_groups => |e| e.getEncLen(),
                .signature_algorithms => |e| e.getEncLen(),
                .supported_versions => |e| e.getEncLen(),
                .key_share => |e| e.getEncLen(),
            };
            try writer.writeIntBig(u16, @intCast(u16, data_len));

            try switch (self.*) {
                .supported_groups => |e| e.encode(writer),
                .signature_algorithms => |e| e.encode(writer),
                .supported_versions => |e| e.encode(writer),
                .key_share => |e| e.encode(writer),
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
        pub fn encode(self: *const Self, writer: anytype) BufferError!void {
            const slice = self.named_group_list.constSlice();

            try writer.writeIntBig(u16, @intCast(u16, slice.len * 2));
            for (slice) |group| {
                try writer.writeIntBig(u16, @enumToInt(group));
            }
        }
    };

    pub const SignatureAlgorithms = struct {
        const Algorithms = std.BoundedArray(SignatureScheme, 65536 / @sizeOf(SignatureScheme));
        supported_algorithms: Algorithms,

        const Self = @This();

        pub fn init() Self {
            var supports = Algorithms.init(0) catch unreachable;
            return Self{
                .supported_algorithms = supports,
            };
        }

        pub fn append(self: *Self, scheme: SignatureScheme) error{Overflow}!void {
            try self.supported_algorithms.append(scheme);
        }

        pub fn appendSlice(self: *Self, schemes: []const SignatureScheme) error{Overflow}!void {
            try self.supported_algorithms.appendSlice(schemes);
        }

        /// get encoded bytes size
        pub fn getEncLen(self: *const Self) usize {
            var len: usize = 0;
            len += @sizeOf(u16); // length field
            len += @sizeOf(SignatureScheme) * self.supported_algorithms.len;
            return len;
        }

        /// encode self to writer
        pub fn encode(self: *const Self, writer: anytype) BufferError!void {
            const slice = self.supported_algorithms.constSlice();

            try writer.writeIntBig(u16, @intCast(u16, slice.len * @sizeOf(u16)));
            for (slice) |algo| {
                try writer.writeIntBig(u16, @enumToInt(algo));
            }
        }
    };

    /// only tls 1.3 is supported
    pub const SupportedVersions = struct {
        const Versions = std.BoundedArray(u16, 128);

        versions: Versions,

        pub const TLS13 = 0x0304;
        const Self = @This();

        pub fn init() Self {
            return .{ .versions = Versions.init(0) catch unreachable };
        }

        pub fn append(self: *Self, version: u16) error{Overflow}!void {
            try self.versions.append(version);
        }

        /// get encoded bytes size
        pub fn getEncLen(self: *const Self) usize {
            return blk: {
                var temp: usize = 0;
                temp += @sizeOf(u8);
                temp += @sizeOf(u16) * self.versions.len;
                break :blk temp;
            };
        }

        /// encode self to writer
        pub fn encode(self: *const Self, writer: anytype) BufferError!void {
            try writer.writeIntBig(u8, @as(u8, @sizeOf(u16)));
            for (self.versions.constSlice()) |version| {
                try writer.writeIntBig(u16, @as(u16, version));
            }
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
        pub fn encode(self: *const Self, writer: anytype) BufferError!void {
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

    test "Extension" {
        var buf = Buffer(1024).init();

        // supported groups
        var sg_ext = sg_ext: {
            var sg = SupportedGroups.init();
            try sg.append(.x25519);
            break :sg_ext Extension{ .supported_groups = sg };
        };
        defer sg_ext.deinit();
        try sg_ext.encode(buf.writer());
        try testing.expectFmt(
            "000A00040002001D",
            "{s}",
            .{std.fmt.fmtSliceHexUpper(buf.getUnreadSlice())},
        );
        try testing.expectEqual(buf.unreadLength(), sg_ext.getEncLen());

        // signature algorithms
        buf.clear();
        var sa_ext = sa_ext: {
            var sa = SignatureAlgorithms.init();
            try sa.appendSlice(&[_]SignatureScheme{
                .ecdsa_secp256r1_sha256,
                .rsa_pss_rsae_sha256,
                .rsa_pksc1_sha256,
            });
            break :sa_ext Extension{ .signature_algorithms = sa };
        };
        defer sa_ext.deinit();
        try sa_ext.encode(buf.writer());
        try testing.expectFmt(
            "000D00080006040308040401",
            "{s}",
            .{std.fmt.fmtSliceHexUpper(buf.getUnreadSlice())},
        );
        try testing.expectEqual(buf.unreadLength(), sa_ext.getEncLen());

        // supported versions
        buf.clear();
        var sv_ext = sv_ext: {
            var sv = SupportedVersions.init();
            try sv.append(SupportedVersions.TLS13);
            break :sv_ext Extension{ .supported_versions = sv };
        };
        defer sv_ext.deinit();
        try sv_ext.encode(buf.writer());
        try testing.expectFmt(
            "002B0003020304",
            "{s}",
            .{std.fmt.fmtSliceHexUpper(buf.getUnreadSlice())},
        );
        try testing.expectEqual(buf.unreadLength(), sv_ext.getEncLen());

        // key share
        buf.clear();
        var ks_ext = ks_ext: {
            var ks = KeyShare.init(testing.allocator);
            break :ks_ext Extension{ .key_share = ks };
        };
        defer ks_ext.deinit();
        try ks_ext.encode(buf.writer());
        try testing.expectFmt(
            "003300020000",
            "{s}",
            .{std.fmt.fmtSliceHexUpper(buf.getUnreadSlice())},
        );
        try testing.expectEqual(buf.unreadLength(), ks_ext.getEncLen());
    }
};

test "all namespace" {
    _ = Provider;
    _ = Handshake;
    _ = extension;
}

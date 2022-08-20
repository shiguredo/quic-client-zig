const std = @import("std");
const crypto = std.crypto;
const io = std.io;
const mem = std.mem;
const testing = std.testing;

const q_crypto = @import("crypto.zig");
const util = @import("util.zig");

const Hmac = crypto.auth.hmac.sha2.HmacSha256;
const Hkdf = crypto.kdf.hkdf.HkdfSha256;

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

    /// implemented only for .{.client_hello} .
    pub fn writeBuffer(self: *Self, out: []u8) util.WriteError!usize {
        var offset: usize = 0;
        const msg_type = @enumToInt(@as(HandshakeType, self.*));
        offset += try util.writeIntReturnSize(u8, out[offset..], msg_type);

        const len_pos = offset;

        offset += @as(usize, @bitSizeOf(u24) / 8);
        const len = switch (self.*) {
            .client_hello => |c_hello| try c_hello.writeBuffer(out[offset..]),
            .server_hello => unreachable,
        };

        _ = try util.writeIntReturnSize(u24, out[len_pos .. len_pos + 3], @intCast(u24, len));

        return offset + len;
    }
};

/// TLS 1.3 ClientHello
pub const ClientHello = struct {
    const LEGACY_VERSION: u16 = 0x0303;
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

        try instance.extensions.append(
            .{ .supported_groups = try extension.SupportedGroups.init() },
        );
        try instance.extensions.append(
            .{ .signature_algorithms = try extension.SignatureAlgorithms.init() },
        );
        try instance.extensions.append(
            .{ .supported_versions = extension.SupportedVersions.init() },
        );
        try instance.extensions.append(
            .{ .key_share = try extension.KeyShare.init(allocator) },
        );

        return instance;
    }

    pub fn deinit(self: *Self) void {
        for (self.extensions.items) |*ext| {
            ext.deinit();
        }
        self.extensions.deinit();
    }

    /// writes to buffer and returns write count 
    pub fn writeBuffer(self: *const Self, out: []u8) util.WriteError!usize {
        var offset: usize = 0;

        // legacy_version
        offset += try util.writeIntReturnSize(u16, out[offset..], LEGACY_VERSION);

        // ramdom
        offset += try util.copyReturnSize(out[offset..], &self.random_bytes);

        // legacy_session_id
        offset += try util.writeIntReturnSize(u8, out[offset..], @intCast(u8, self.legacy_session_id.len));
        offset += try util.copyReturnSize(out[offset..], self.legacy_session_id.constSlice());

        // cipher_suites
        const suites_byte_ptr = mem.sliceAsBytes(self.cipher_suites.constSlice());
        offset += try util.writeIntReturnSize(u16, out[offset..], @intCast(u16, suites_byte_ptr.len));
        offset += try util.copyReturnSize(out[offset..], suites_byte_ptr);

        // legacy_compression_methods
        offset += try util.writeIntReturnSize(u8, out[offset..], @intCast(u8, self.legacy_compression_methods.len));
        offset += try util.copyReturnSize(out[offset..], self.legacy_compression_methods.constSlice());

        // extensions
        const ext_len_offset = offset;
        offset += @as(usize, @sizeOf(u16));
        var ext_total_len: usize = 0;
        for (self.extensions.items) |*ext| {
            const ext_len = try ext.writeBuffer(out[offset..]);
            offset += ext_len;
            ext_total_len += ext_len;
        }
        // write sum of extension len
        _ = try util.writeIntReturnSize(u16, out[ext_len_offset .. ext_len_offset + @sizeOf(u16)], @intCast(u16, ext_total_len));

        return offset;
    }
};

pub const ServerHello = struct {};

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

        /// writes to buffer and returns write count 
        pub fn writeBuffer(self: *const Self, out: []u8) util.WriteError!usize {
            var offset: usize = 0;
            const ext_type = @as(ExtensionType, self.*);
            offset += try util.writeIntReturnSize(u16, out[offset..], @enumToInt(ext_type));
            const len_pos = offset;
            offset += @as(usize, @sizeOf(u16));

            var data_field_out = out[offset..];
            const data_len = try switch (self.*) {
                .supported_groups => |e| e.writeBuffer(data_field_out),
                .signature_algorithms => |e| e.writeBuffer(data_field_out),
                .supported_versions => |e| e.writeBuffer(data_field_out),
                .key_share => |e| e.writeBuffer(data_field_out),
            };

            _ = try util.writeIntReturnSize(u16, out[len_pos .. len_pos + @sizeOf(u16)], @intCast(u16, data_len));

            return len_pos + data_len + @as(usize, @sizeOf(u16));
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

        pub fn writeBuffer(self: *const Self, out: []u8) util.WriteError!usize {
            var offset: usize = 0;

            const slice = self.named_group_list.constSlice();

            offset += try util.writeIntReturnSize(u16, out[offset..], @intCast(u16, slice.len * 2));
            for (slice) |group| {
                offset += try util.writeIntReturnSize(u16, out[offset..], @enumToInt(group));
            }

            return offset;
        }
    };

    pub const SignatureAlgorithms = struct {
        const Algorithms = std.BoundedArray(SignatureScheme, 65536 / @sizeOf(SignatureScheme));
        supported_algorithms: Algorithms,

        const Self = @This();

        pub fn init() !Self {
            var supports = try Algorithms.init(0);
            try supports.append(.ecdsa_secp256r1_sha256);
            return Self{
                .supported_algorithms = supports,
            };
        }

        pub fn writeBuffer(self: *const Self, out: []u8) util.WriteError!usize {
            var offset: usize = 0;
            const bytes = mem.sliceAsBytes(self.supported_algorithms.constSlice());

            offset += try util.writeIntReturnSize(u16, out[offset..], @intCast(u16, bytes.len));
            offset += try util.copyReturnSize(out[offset..], bytes);
            return offset;
        }
    };

    /// only tls 1.3 is supported
    pub const SupportedVersions = struct {
        pub const TLS13 = 0x0304;
        const Self = @This();

        pub fn init() Self {
            return .{};
        }

        pub fn writeBuffer(self: *const Self, out: []u8) util.WriteError!usize {
            _ = self;
            var offset: usize = 0;
            offset += try util.writeIntReturnSize(u8, out[offset..], @as(u8, @sizeOf(u16)));
            offset += try util.writeIntReturnSize(u16, out[offset..], @as(u16, TLS13));
            return offset;
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

        pub fn writeBuffer(self: *const Self, out: []u8) util.WriteError!usize {
            var offset: usize = @sizeOf(u16);
            for (self.shares.items) |*share| {
                offset += try util.writeIntReturnSize(u16, out[offset..], @enumToInt(share.group));
                offset += try util.writeIntReturnSize(u16, out[offset..], @intCast(u16, self.shares.items.len));
                offset += try util.copyReturnSize(out[offset..], share.key_exchange.items);
            }
            _ = try util.writeIntReturnSize(u16, out[0..], @intCast(u16, offset - @as(usize, @sizeOf(u16))));
            return offset;
        }
    };
};

test "client hello" {
    var client_hello = try Handshake.initClient(testing.allocator);
    defer client_hello.deinit();
    var buf: [65536]u8 = undefined;
    const len = try client_hello.writeBuffer(&buf);
    const before_random = buf[0..6];
    const after_random = buf[6 + 32 .. len];
    try testing.expectEqual(@as(u8, 0x01), buf[0]); // handshake type "ClientHello"
    try testing.expectEqual(len - 4, @intCast(usize, mem.readInt(u24, before_random[1..4], .Big))); // length field of handshake
    try testing.expectEqual(@as(u16, 0x0303), mem.readInt(u16, before_random[4..6], .Big)); // legacy_version == 0x0303

    try testing.expectFmt(
        ("00" ++ // legacy_session_id
            "00021301" ++ // cipher_suites
            "0100" ++ // legacy_compression_id
            "001D" ++ // extension field length
            "000A00040002001D" ++ // supported_groups
            "000D000400020304" ++ // sigunature_algorithms
            "002B0003020304" ++ // supported_versions
            "003300020000"), // key_share
        "{s}",
        .{std.fmt.fmtSliceHexUpper(after_random)},
    );
}

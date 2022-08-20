const std = @import("std");
const crypto = std.crypto;
const q_crypto = @import("crypto.zig");
const io = std.io;
const mem = std.mem;
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

pub const Handshake = struct {
    msg_type: HandshakeType,
    length: u24,
    content: Content,

    const Self = @This();

    pub const HandshakeType = enum(u8) {
        client_hello = 0x01,
        server_hello = 0x02,
    };

    const Content = union(HandshakeType) {
        client_hello: ClientHello,
        server_hello: ServerHello,
    };

    pub fn writeBuffer(self: *Self, out: []u8) util.WriteError!usize {
        var offset: usize = 0;
        offset += try util.writeIntReturnSize(u8, out[offset..], @enumToInt(self.msg_type));
    }
};

/// TLS 1.3 ClientHello
pub const ClientHello = struct {
    const LEGACY_VERSION: u16 = 0x0303;

    random_byte: [32]u8,
    legacy_session_id: std.ArrayList(u8),
    cipher_suites: std.ArrayList([2]u8),
    legacy_compression_methods: std.ArrayList(u8),
    extensions: std.ArrayList(extension.Extension),

    const Self = @This();

    pub fn init() !Self {}

    /// writes to buffer and returns write count 
    pub fn writeBuffer(self: *const Self, out: []u8) util.WriteError!usize {
        var offset: usize = 0;
        offset += try util.writeIntReturnSize(u16, out[offset..], LEGACY_VERSION);

        offset += try util.copyWithOffset(out[offset..], &self.random_byte);

        offset += try util.writeIntReturnSize(u8, out[offset..], @intCast(u8, self.legacy_session_id.items.len));

        offset += try util.copyWithOffset(out[offset..], self.legacy_session_id.items);

        const suites_byte_ptr = mem.asBytes(self.cipher_suites.items);
        offset += try util.writeIntReturnSize(u16, out[offset..], @intCast(u16, suites_byte_ptr.len));
        offset += try util.copyWithOffset(out[offset..], suites_byte_ptr);

        // extensions
        const ext_len_offset = offset;
        offset += @sizeof(u16);
        var ext_total_len: usize = 0;
        for (self.extensions) |ext, index| {
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

    pub const ReadError = error{
        BufferShortError,
    };

    pub const Extension = union(ExtensionType) {
        supported_groups: SupportedGroups,
        signature_algorithms: SignatureAlgorithms,
        supported_versions: SupportedVersions,
        key_share: KeyShare,

        const Self = @This();

        /// writes to buffer and returns write count 
        pub fn writeBuffer(self: *const Self, out: []u8) util.WriteError!usize {
            var offset: usize = 0;
            const ext_type = @as(ExtensionType, self);
            offset += try util.writeIntReturnSize(u16, out[offset..], @enumToInt(ext_type));
            const len_pos = offset;

            const data_len = try switch (self) {
                .supported_groups => |e| e.writeBuffer(out),
                .signature_algorithms => |e| e.writeBuffer(out),
                .supported_versions => |e| e.writeBuffer(out),
                .key_share => |e| e.writeBuffer(out),
            };

            _ = try util.writeIntReturnSize(u16, out[len_pos .. len_pos + @sizeOf(u16)], data_len);

            return len_pos + data_len + @sizeof(u16);
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

    pub const SignatureScheme = union(u16) {
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
        named_group_list: std.ArrayList(NamedGroup),

        const Self = @This();

        pub fn writeBuffer(self, out: []u8) util.WriteError!usize {
            var offset: usize = 0;
            const bytes = mem.asBytes(self.named_group_list.items);

            offset += try util.writeIntReturnSize(u16, out[offset..], @intCast(u16, bytes.len));
            offset += try util.copyReturnSize(out[offset..], bytes);
            return offset;
        }
    };

    pub const SignatureAlgorithms = struct {
        supported_algorithms: std.ArrayList(SignatureScheme),

        const Self = @This();

        pub fn writeBuffer(self: *Self, out: []u8) util.WriteError!usize {
            var offset: usize = 0;
            const bytes = mem.asBytes(self.supported_algorithms.items);

            offset += try util.writeIntReturnSize(u16, out[offset..], @intCast(u16, bytes.len));
            offset += try util.copyReturnSize(out[offset..], bytes);
            return offset;
        }
    };

    /// only tls 1.3 is supported
    pub const SupportedVersions = struct {
        pub const TLS13 = 0x0304;
        const Self = @This();

        pub fn writeBuffer(self: *Self, out: []u8) util.WriteError!usize {
            var offset: usize = 0;
            offset += try util.writeIntReturnSize(u8, out[offset..], @as(u8, 2));
            offset += try util.writeIntReturnSize(u16, out[offset..], @as(u16, TLS13));
            return offset;
        }
    };

    /// KeyShareClientHello
    pub const KeyShare = struct {
        shares: std.ArrayList(KeyShareEntry),

        const Self = @This();

        const KeyShareEntry = struct {
            group: NamedGroup,
            key_exchange: std.ArrayList(u8),
        };

        pub fn writeBuffer(self: *Self, out: []u8) util.WriteError!void {
            var offset: usize = 2;
            for (self.shares.items) |share| {
                offset += try util.writeIntReturnSize(u16, out[offset..], @enumToInt(share.group));
                offset += try util.writeIntReturnSize(u16, out[offset..], @intCast(u16, self.shares.items.len));
                offset += try util.copyReturnSize(out[offset..], self.shares.items);
            }
            return offset;
        }
    };
};

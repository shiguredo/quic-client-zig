const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const meta = std.meta;
const io = std.io;
const fmt = std.fmt;
const testing = std.testing;
const math = std.math;

const util = @import("util.zig");
const tls = @import("tls.zig");
const PacketTypes = @import("packet.zig").PacketTypes;

pub const Sha256 = crypto.hash.sha2.Sha256;
pub const Hmac = crypto.auth.hmac.sha2.HmacSha256;
pub const Hkdf = crypto.kdf.hkdf.HkdfSha256;

// zig fmt: off
pub const INITIAL_SALT_V1 = [_]u8{
    0x38, 0x76, 0x2c, 0xf7,
    0xf5, 0x59, 0x34, 0xb3,
    0x4d, 0x17, 0x9a, 0xe6,
    0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
};
// zig fmt: on

pub const HkdfAbst = struct {
    hash_type: HashTypes,
    mac_length: usize,
    vtable: *const VTable,

    pub const KEY_LENGTH = 32;

    const Self = @This();

    pub const VTable = struct {
        extract: *const fn (out: []u8, salt: []const u8, ikm: []const u8) void,
        expand: *const fn (out: []u8, ctx: []const u8, prk: []const u8) void,
    };

    pub const HashTypes = enum {
        sha256,
        sha512,
    };

    // To avoid bus error, we have to create instances at compile time.
    const instance_sha256 = Self._createComptime(.sha256);
    const instance_sha512 = Self._createComptime(.sha512);

    pub fn get(hash: HashTypes) Self {
        return switch (hash) {
            .sha256 => instance_sha256,
            .sha512 => instance_sha512,
        };
    }

    fn _createComptime(comptime hash: HashTypes) Self {
        const vtable = switch (hash) {
            .sha256 => _vtableFromHmac(crypto.auth.hmac.sha2.HmacSha256),
            .sha512 => _vtableFromHmac(crypto.auth.hmac.sha2.HmacSha512),
        };

        const mac_length = switch (hash) {
            .sha256 => crypto.auth.hmac.sha2.HmacSha256.mac_length,
            .sha512 => crypto.auth.hmac.sha2.HmacSha512.mac_length,
        };

        return .{
            .hash_type = hash,
            .mac_length = mac_length,
            .vtable = &vtable,
        };
    }

    fn _vtableFromHmac(comptime HmacType: type) VTable {
        const HkdfType = crypto.kdf.hkdf.Hkdf(HmacType);
        const S = struct {
            pub fn extract(out: []u8, salt: []const u8, ikm: []const u8) void {
                const extracted = HkdfType.extract(salt, ikm);
                mem.copy(u8, out, &extracted);
            }

            pub fn expand(out: []u8, ctx: []const u8, prk: []const u8) void {
                var prk_buf: [HmacType.mac_length]u8 = undefined;
                mem.copy(u8, &prk_buf, prk[0..prk_buf.len]);
                HkdfType.expand(out, ctx, prk_buf);
            }
        };

        const vtable = VTable{
            .extract = S.extract,
            .expand = S.expand,
        };

        return vtable;
    }

    pub inline fn extract(self: Self, out: []u8, salt: []const u8, ikm: []const u8) void {
        self.vtable.extract(out, salt, ikm);
    }

    pub inline fn expand(self: Self, out: []u8, ctx: []const u8, prk: []const u8) void {
        self.vtable.expand(out, ctx, prk);
    }

    /// Defined here: https://www.rfc-editor.org/rfc/rfc8446#section-7.1
    /// `secret.len` must be `HkdfAbst.KEY_LENGTH`, which is 32
    pub fn expandLabel(
        self: Self,
        out: []u8,
        secret: []const u8,
        label: []const u8,
        context: []const u8,
    ) void {
        const MAX_LABEL_LEN = 512;
        var label_buf: [MAX_LABEL_LEN]u8 = undefined;
        const _label = _makeLabel(&label_buf, label, context, out.len);
        self.expand(out, _label, secret);
    }

    /// `out` must be longer than 255 + 255 + 2 = 512 bytes
    fn _makeLabel(out_buf: []u8, label: []const u8, context: []const u8, length: usize) []u8 {
        const PREFIX = "tls13 ";
        var stream = io.fixedBufferStream(out_buf);
        var writer = stream.writer();
        writer.writeIntBig(u16, @intCast(u16, length)) catch unreachable;
        writer.writeIntBig(u8, @intCast(u8, PREFIX.len + label.len)) catch unreachable;
        writer.writeAll(PREFIX) catch unreachable;
        writer.writeAll(label) catch unreachable;
        writer.writeIntBig(u8, @intCast(u8, context.len)) catch unreachable;
        writer.writeAll(context) catch unreachable;
        return stream.getWritten();
    }
};

pub const AeadAbst = struct {
    aead_type: AeadTypes,
    tag_length: usize,
    nonce_length: usize,
    key_length: usize,
    vtable: *const VTable,

    const Self = @This();

    pub const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
    pub const Aes256Gcm = crypto.aead.aes_gcm.Aes256Gcm;
    pub const ChaCha20Poly1305 = crypto.aead.chacha_poly.ChaCha20Poly1305;

    pub const TAG_LENGTH = 16;

    pub const MAX_NONCE_LENGTH = math.max3(
        Aes128Gcm.nonce_length,
        Aes256Gcm.nonce_length,
        ChaCha20Poly1305.nonce_length,
    );

    pub const MAX_KEY_LENGTH = math.max3(
        Aes128Gcm.key_length,
        Aes256Gcm.key_length,
        ChaCha20Poly1305.key_length,
    );

    pub const AeadTypes = enum {
        aes128gcm,
        aes256gcm,
        chacha20poly1305,
    };

    pub const AuthenticationError = error{AuthenticationFailed};

    pub const VTable = struct {
        encrypt: *const fn (
            c: []u8,
            tag: []u8,
            m: []const u8,
            ad: []const u8,
            npub: []const u8,
            key: []const u8,
        ) void,
        decrypt: *const fn (
            m: []u8,
            c: []const u8,
            tag: []const u8,
            ad: []const u8,
            npub: []const u8,
            key: []const u8,
        ) AuthenticationError!void,
    };

    pub inline fn encrypt(
        self: Self,
        c: []u8,
        tag: []u8,
        m: []const u8,
        ad: []const u8,
        npub: []const u8,
        key: []const u8,
    ) void {
        self.vtable.encrypt(c, tag, m, ad, npub, key);
    }

    pub inline fn decrypt(
        self: Self,
        m: []u8,
        c: []const u8,
        tag: []const u8,
        ad: []const u8,
        npub: []const u8,
        key: []const u8,
    ) AuthenticationError!void {
        try self.vtable.decrypt(m, c, tag, ad, npub, key);
    }

    const instance_aes128gcm = _createComptime(Aes128Gcm);
    const instance_aes256gcm = _createComptime(Aes256Gcm);
    const instance_chacha20poly1305 = _createComptime(ChaCha20Poly1305);

    pub fn get(aead_type: AeadTypes) Self {
        return switch (aead_type) {
            .aes128gcm => instance_aes128gcm,
            .aes256gcm => instance_aes256gcm,
            .chacha20poly1305 => instance_chacha20poly1305,
        };
    }

    fn _createComptime(comptime AeadType: type) Self {
        const vtable = _vtable(AeadType);

        const aead_type: AeadTypes = switch (AeadType) {
            Aes128Gcm => .aes128gcm,
            Aes256Gcm => .aes256gcm,
            ChaCha20Poly1305 => .chacha20poly1305,
            else => @compileError("Compile error: Aead type invalid."),
        };

        return .{
            .aead_type = aead_type,
            .tag_length = AeadType.tag_length,
            .nonce_length = AeadType.nonce_length,
            .key_length = AeadType.key_length,
            .vtable = &vtable,
        };
    }

    fn _vtable(comptime AeadType: type) VTable {
        const S = struct {
            const tag_len = AeadType.tag_length;
            const nonce_len = AeadType.nonce_length;
            const key_length = AeadType.key_length;
            pub fn encrypt(
                c: []u8,
                tag: []u8,
                m: []const u8,
                ad: []const u8,
                npub: []const u8,
                key: []const u8,
            ) void {
                AeadType.encrypt(c, tag[0..tag_len], m, ad, npub[0..nonce_len].*, key[0..key_length].*);
            }

            pub fn decrypt(
                m: []u8,
                c: []const u8,
                tag: []const u8,
                ad: []const u8,
                npub: []const u8,
                key: []const u8,
            ) AuthenticationError!void {
                try AeadType.decrypt(m, c, tag[0..tag_len].*, ad, npub[0..nonce_len].*, key[0..key_length].*);
            }
        };
        return .{
            .encrypt = S.encrypt,
            .decrypt = S.decrypt,
        };
    }
};

test "HkdfAbst.expandLabel()" {
    const hkdf256 = HkdfAbst.get(.sha256);
    const secret =
        "\x33\xad\x0a\x1c\x60\x7e\xc0\x3b\x09\xe6\xcd\x98\x93\x68\x0c\xe2" ++
        "\x10\xad\xf3\x00\xaa\x1f\x26\x60\xe1\xb2\x2e\x10\xf1\x70\xf9\x2a";
    const label = "derived";
    const context =
        "\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24" ++
        "\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55";
    const expected_hex =
        "6f2615a108c702c5678f54fc9dbab697" ++
        "16c076189c48250cebeac3576c3611ba";
    var buf = [_]u8{0} ** 32;
    hkdf256.expandLabel(&buf, secret, label, context);
    try testing.expectFmt(expected_hex, "{x}", .{fmt.fmtSliceHexLower(&buf)});
}

test "AeadAbst" {
    const aes128gcm = AeadAbst.get(.aes128gcm);
    const key = [_]u8{0x69} ** 32;
    const nonce = [_]u8{0x42} ** 12;
    const m = "Test with message";
    const ad = "Test with associated data";
    var c: [m.len]u8 = undefined;
    var m2: [m.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    aes128gcm.encrypt(&c, &tag, m, ad, &nonce, &key);
    try aes128gcm.decrypt(&m2, &c, &tag, ad, &nonce, &key);

    try testing.expectEqualStrings(m, &m2);
}

/// struct that consists of secret, key, iv, and encryption algorithm for QUIC packet protection.
/// TODO: replace tls.QuicKeys with this.
pub const QuicKeys = struct {
    hkdf: HkdfAbst,
    aead: AeadAbst,

    secret: [HkdfAbst.KEY_LENGTH]u8 = undefined,
    key: Key = undefined,
    iv: Iv = undefined,
    hp: Hp = undefined,

    pub const Key = std.BoundedArray(u8, AeadAbst.MAX_KEY_LENGTH);
    pub const Iv = std.BoundedArray(u8, AeadAbst.MAX_NONCE_LENGTH);
    pub const Hp = std.BoundedArray(u8, AeadAbst.MAX_KEY_LENGTH);

    const Self = @This();

    /// derive self's keys with its secret
    pub fn deriveKeysFromSecret(secret: [HkdfAbst.KEY_LENGTH]u8, hkdf: HkdfAbst, aead: AeadAbst) Self {
        var instance = Self{ .hkdf = hkdf, .aead = aead, .secret = secret };
        instance.key = Key.init(aead.key_length) catch unreachable;
        instance.iv = Iv.init(aead.nonce_length) catch unreachable;
        instance.hp = Hp.init(aead.key_length) catch unreachable;
        instance.hkdf.expandLabel(instance.key.slice(), &secret, "quic key", "");
        instance.hkdf.expandLabel(instance.iv.slice(), &secret, "quic iv", "");
        instance.hkdf.expandLabel(instance.hp.slice(), &secret, "quic hp", "");
        return instance;
    }
};

test "QuicKeys" {
    const secret_hex = "c00cf151ca5be075ed0ebfb5c80323c4" ++ "2d6b7db67881289af4008f1f6c357aea";
    var secret = [_]u8{0} ** HkdfAbst.KEY_LENGTH;
    _ = try fmt.hexToBytes(&secret, secret_hex);
    const hkdf = HkdfAbst.get(.sha256);
    const aead = AeadAbst.get(.aes128gcm);
    const keys = QuicKeys.deriveKeysFromSecret(secret, hkdf, aead);

    // client initial key
    try testing.expectFmt(
        "1f369613dd76d5467730efcbe3b1a22d",
        "{s}",
        .{std.fmt.fmtSliceHexLower(keys.key.constSlice())},
    );

    // client iv
    try testing.expectFmt(
        "fa044b2f42a3fd3b46fb255c",
        "{s}",
        .{std.fmt.fmtSliceHexLower(keys.iv.constSlice())},
    );

    // client hp key
    try testing.expectFmt(
        "9f50449e04a0e810283a1e9933adedd2",
        "{s}",
        .{std.fmt.fmtSliceHexLower(keys.hp.constSlice())},
    );
}

pub const QuicKeyBinder = struct {
    initial: QuicKeys,
    handshake: QuicKeys,
    zero_rtt: QuicKeys,
    one_rtt: QuicKeys,

    const Self = @This();

    pub fn getByPacketType(self: Self, p_type: PacketTypes) QuicKeys {
        return switch (p_type) {
            .initial => self.initial,
            .handshake => self.handshake,
            .zero_rtt => self.zero_rtt,
            .one_rtt => self.one_rtt,
            else => unreachable, // TODO: handling version negotiation
        };
    }
};

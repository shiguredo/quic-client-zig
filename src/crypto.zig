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

pub const Sha256 = crypto.hash.sha2.Sha256;
pub const Hmac = crypto.auth.hmac.sha2.HmacSha256;
pub const Hkdf = crypto.kdf.hkdf.HkdfSha256;

const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

// zig fmt: off
pub const INITIAL_SALT_V1 = [_]u8{
    0x38, 0x76, 0x2c, 0xf7,
    0xf5, 0x59, 0x34, 0xb3,
    0x4d, 0x17, 0x9a, 0xe6,
    0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
};
// zig fmt: on

pub fn hkdfExpandLabel(
    out: []u8,
    secret: [Hmac.key_length]u8,
    label: []const u8,
    context: []const u8,
) void {
    const LABEL_PREFIX = "tls13 ";
    const out_len = @intCast(u16, out.len);

    const MAX_INFO_LEN = 600;

    var hkdf_label: [MAX_INFO_LEN]u8 = undefined;

    var offset: usize = 0;
    std.mem.writeIntSlice(u16, hkdf_label[offset..(offset + @sizeOf(u16))], out_len, .Big);
    offset += @sizeOf(u16);

    hkdf_label[offset] = @intCast(u8, LABEL_PREFIX.len + label.len);
    offset += @sizeOf(u8);

    std.mem.copy(u8, hkdf_label[offset..(offset + LABEL_PREFIX.len)], LABEL_PREFIX);
    offset += LABEL_PREFIX.len;

    std.mem.copy(u8, hkdf_label[offset..(offset + label.len)], label);
    offset += label.len;

    hkdf_label[offset] = @intCast(u8, context.len);
    offset += @sizeOf(u8);

    std.mem.copy(u8, hkdf_label[offset..(offset + context.len)], context);
    offset += context.len;

    Hkdf.expand(out, hkdf_label[0..offset], secret);
}

test "HKDF-Expand-Label" {
    const random_bytes = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
    const initial_secret = Hkdf.extract(&INITIAL_SALT_V1, &random_bytes);
    var client_initial: [Hmac.key_length]u8 = undefined;
    hkdfExpandLabel(&client_initial, initial_secret, "client in", "");

    var client_key: [16]u8 = undefined;
    hkdfExpandLabel(&client_key, client_initial, "quic key", "");

    // zig fmt: off
    const expected = [_]u8{ 
        0xb1, 0x4b, 0x91, 0x81,
        0x24, 0xfd, 0xa5, 0xc8,
        0xd7, 0x98, 0x47, 0x60,
        0x2f, 0xa3, 0x52, 0x0b,
    };
    // zig fmt: on

    try testing.expectEqual(expected, client_key);
}

pub fn deriveSecret(
    out: *[Sha256.digest_length]u8,
    secret: [Hmac.key_length]u8,
    label: []const u8,
    message: []const u8,
) void {
    var h: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(message, &h, .{});

    hkdfExpandLabel(out, secret, label, &h);
}

// test vectors from https://www.rfc-editor.org/rfc/rfc8448.html#section-3
test "Derive-Secret" {
    const handshake_secret =
        "\x1d\xc8\x26\xe9\x36\x06\xaa\x6f\xdc\x0a\xad\xc1\x2f\x74\x1b" ++
        "\x01\x04\x6a\xa6\xb9\x9f\x69\x1e\xd2\x21\xa9\xf0\xca\x04\x3f" ++
        "\xbe\xac";
    const client_hello_bytes =
        "\x01\x00\x00\xc0\x03\x03\xcb\x34\xec\xb1\xe7\x81\x63\xba\x1c\x38\xc6\xda\xcb\x19\x6a" ++
        "\x6d\xff\xa2\x1a\x8d\x99\x12\xec\x18\xa2\xef\x62\x83\x02\x4d\xec\xe7\x00\x00\x06\x13" ++
        "\x01\x13\x03\x13\x02\x01\x00\x00\x91\x00\x00\x00\x0b\x00\x09\x00\x00\x06\x73\x65\x72" ++
        "\x76\x65\x72\xff\x01\x00\x01\x00\x00\x0a\x00\x14\x00\x12\x00\x1d\x00\x17\x00\x18\x00" ++
        "\x19\x01\x00\x01\x01\x01\x02\x01\x03\x01\x04\x00\x23\x00\x00\x00\x33\x00\x26\x00\x24" ++
        "\x00\x1d\x00\x20\x99\x38\x1d\xe5\x60\xe4\xbd\x43\xd2\x3d\x8e\x43\x5a\x7d\xba\xfe\xb3" ++
        "\xc0\x6e\x51\xc1\x3c\xae\x4d\x54\x13\x69\x1e\x52\x9a\xaf\x2c\x00\x2b\x00\x03\x02\x03" ++
        "\x04\x00\x0d\x00\x20\x00\x1e\x04\x03\x05\x03\x06\x03\x02\x03\x08\x04\x08\x05\x08\x06" ++
        "\x04\x01\x05\x01\x06\x01\x02\x01\x04\x02\x05\x02\x06\x02\x02\x02\x00\x2d\x00\x02\x01" ++
        "\x01\x00\x1c\x00\x02\x40\x01";
    const server_hello_bytes =
        "\x02\x00\x00\x56\x03\x03\xa6\xaf\x06\xa4\x12\x18\x60\xdc\x5e\x6e\x60\x24\x9c\xd3\x4c" ++
        "\x95\x93\x0c\x8a\xc5\xcb\x14\x34\xda\xc1\x55\x77\x2e\xd3\xe2\x69\x28\x00\x13\x01\x00" ++
        "\x00\x2e\x00\x33\x00\x24\x00\x1d\x00\x20\xc9\x82\x88\x76\x11\x20\x95\xfe\x66\x76\x2b" ++
        "\xdb\xf7\xc6\x72\xe1\x56\xd6\xcc\x25\x3b\x83\x3d\xf1\xdd\x69\xb1\xb0\x4e\x75\x1f\x0f" ++
        "\x00\x2b\x00\x02\x03\x04";
    const message = try mem.concat(
        testing.allocator,
        u8,
        &[_][]const u8{ mem.span(client_hello_bytes), mem.span(server_hello_bytes) },
    );
    defer testing.allocator.free(message);
    var client_handshake_traffic_secret: [Sha256.digest_length]u8 = undefined;
    deriveSecret(
        &client_handshake_traffic_secret,
        handshake_secret.*,
        "c hs traffic",
        message,
    );
    try testing.expectFmt(
        "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21",
        "{x}",
        .{std.fmt.fmtSliceHexLower(&client_handshake_traffic_secret)},
    );
}

pub const HP_KEY_LENGTH = 16;

/// given header and payload, return encrypted packet array list
/// header is from first byte to packet number field,
/// payload is remainder (does not include packet number field)
pub fn encryptPacket(
    comptime AesGcm: type,
    header: []const u8,
    payload: []const u8,
    key: [AesGcm.key_length]u8,
    iv: [AesGcm.nonce_length]u8,
    hp_key: [HP_KEY_LENGTH]u8,
    allocator: mem.Allocator,
) !std.ArrayList(u8) {
    // create nonce
    const pn_length = @intCast(usize, header[0] & 0x03) + 1;
    const nonce_len = AesGcm.nonce_length;
    var nonce = [_]u8{0} ** nonce_len;
    mem.copy(u8, &nonce, &iv);
    for (header[header.len - pn_length ..]) |value, index| {
        nonce[nonce_len - pn_length + index] ^= value;
    }

    // encrypt payload
    var protected_payload = try allocator.alloc(u8, payload.len);
    defer allocator.free(protected_payload);
    var auth_tag: [AesGcm.tag_length]u8 = undefined;
    AesGcm.encrypt(protected_payload, &auth_tag, payload, header, nonce, key);

    // get hp sample
    var sample = [_]u8{0} ** HP_KEY_LENGTH;
    mem.copy(u8, &sample, protected_payload[4 - pn_length .. 20 - pn_length]);

    // create header protection mask
    const Aes = switch (AesGcm) {
        std.crypto.aead.aes_gcm.Aes128Gcm => crypto.core.aes.Aes128,
        std.crypto.aead.aes_gcm.Aes256Gcm => crypto.core.aes.Aes256,
        else => @compileError("invalid AesGcm type"),
    };
    const mask = deriveHpMask(Aes, hp_key, sample);

    // apply header protection
    var encrypted_packet = std.ArrayList(u8).init(allocator);
    try encrypted_packet.appendSlice(header);
    encrypted_packet.items[0] ^= (mask[0] & 0x0f);
    for (encrypted_packet.items[header.len - pn_length ..]) |*value, index| {
        value.* ^= mask[1 + index];
    }

    // append payload
    try encrypted_packet.appendSlice(protected_payload);

    // append auth tag
    try encrypted_packet.appendSlice(&auth_tag);

    return encrypted_packet;
}

test "encryptPacket" {
    // test vectors from https://www.rfc-editor.org/rfc/rfc9001#name-sample-packet-protection
    var header_array = [_]u8{0} ** 256;
    const header = try std.fmt.hexToBytes(
        &header_array,
        "c300000001088394c8f03e5157080000449e00000002",
    );
    var payload_array = [_]u8{0} ** 2048;
    // zig fmt: off
    _ = try std.fmt.hexToBytes(
        &payload_array,
        "060040f1010000ed0303ebf8fa56f129" ++ "39b9584a3896472ec40bb863cfd3e868" ++
        "04fe3a47f06a2b69484c000004130113" ++ "02010000c000000010000e00000b6578" ++
        "616d706c652e636f6dff01000100000a" ++ "00080006001d00170018001000070005" ++
        "04616c706e0005000501000000000033" ++ "00260024001d00209370b2c9caa47fba" ++
        "baf4559fedba753de171fa71f50f1ce1" ++ "5d43e994ec74d748002b000302030400" ++
        "0d0010000e0403050306030203080408" ++ "050806002d00020101001c0002400100" ++
        "3900320408ffffffffffffffff050480" ++ "00ffff07048000ffff08011001048000" ++
        "75300901100f088394c8f03e51570806" ++ "048000ffff",
    );
    // zig fmt: on

    const payload_len_with_padding = 1162;
    const payload = payload_array[0..payload_len_with_padding];

    const client_initial = tls.QuicKeys{
        .key = "\x1f\x36\x96\x13\xdd\x76\xd5\x46\x77\x30\xef\xcb\xe3\xb1\xa2\x2d".*,
        .iv = "\xfa\x04\x4b\x2f\x42\xa3\xfd\x3b\x46\xfb\x25\x5c".*,
        .hp = "\x9f\x50\x44\x9e\x04\xa0\xe8\x10\x28\x3a\x1e\x99\x33\xad\xed\xd2".*,
    };

    const encrypted = try encryptPacket(
        Aes128Gcm,
        header,
        payload,
        client_initial.key,
        client_initial.iv,
        client_initial.hp,
        testing.allocator,
    );
    defer encrypted.deinit();

    // zig fmt: off
    try testing.expectFmt(
        "c000000001088394c8f03e5157080000" ++ "449e7b9aec34d1b1c98dd7689fb8ec11" ++
        "d242b123dc9bd8bab936b47d92ec356c" ++ "0bab7df5976d27cd449f63300099f399" ++
        "1c260ec4c60d17b31f8429157bb35a12" ++ "82a643a8d2262cad67500cadb8e7378c" ++
        "8eb7539ec4d4905fed1bee1fc8aafba1" ++ "7c750e2c7ace01e6005f80fcb7df6212" ++
        "30c83711b39343fa028cea7f7fb5ff89" ++ "eac2308249a02252155e2347b63d58c5" ++
        "457afd84d05dfffdb20392844ae81215" ++ "4682e9cf012f9021a6f0be17ddd0c208" ++
        "4dce25ff9b06cde535d0f920a2db1bf3" ++ "62c23e596d11a4f5a6cf3948838a3aec" ++
        "4e15daf8500a6ef69ec4e3feb6b1d98e" ++ "610ac8b7ec3faf6ad760b7bad1db4ba3" ++
        "485e8a94dc250ae3fdb41ed15fb6a8e5" ++ "eba0fc3dd60bc8e30c5c4287e53805db" ++
        "059ae0648db2f64264ed5e39be2e20d8" ++ "2df566da8dd5998ccabdae053060ae6c" ++
        "7b4378e846d29f37ed7b4ea9ec5d82e7" ++ "961b7f25a9323851f681d582363aa5f8" ++
        "9937f5a67258bf63ad6f1a0b1d96dbd4" ++ "faddfcefc5266ba6611722395c906556" ++
        "be52afe3f565636ad1b17d508b73d874" ++ "3eeb524be22b3dcbc2c7468d54119c74" ++
        "68449a13d8e3b95811a198f3491de3e7" ++ "fe942b330407abf82a4ed7c1b311663a" ++
        "c69890f4157015853d91e923037c227a" ++ "33cdd5ec281ca3f79c44546b9d90ca00" ++
        "f064c99e3dd97911d39fe9c5d0b23a22" ++ "9a234cb36186c4819e8b9c5927726632" ++
        "291d6a418211cc2962e20fe47feb3edf" ++ "330f2c603a9d48c0fcb5699dbfe58964" ++
        "25c5bac4aee82e57a85aaf4e2513e4f0" ++ "5796b07ba2ee47d80506f8d2c25e50fd" ++
        "14de71e6c418559302f939b0e1abd576" ++ "f279c4b2e0feb85c1f28ff18f58891ff" ++
        "ef132eef2fa09346aee33c28eb130ff2" ++ "8f5b766953334113211996d20011a198" ++
        "e3fc433f9f2541010ae17c1bf202580f" ++ "6047472fb36857fe843b19f5984009dd" ++
        "c324044e847a4f4a0ab34f719595de37" ++ "252d6235365e9b84392b061085349d73" ++
        "203a4a13e96f5432ec0fd4a1ee65accd" ++ "d5e3904df54c1da510b0ff20dcc0c77f" ++
        "cb2c0e0eb605cb0504db87632cf3d8b4" ++ "dae6e705769d1de354270123cb11450e" ++
        "fc60ac47683d7b8d0f811365565fd98c" ++ "4c8eb936bcab8d069fc33bd801b03ade" ++
        "a2e1fbc5aa463d08ca19896d2bf59a07" ++ "1b851e6c239052172f296bfb5e724047" ++
        "90a2181014f3b94a4e97d117b4381303" ++ "68cc39dbb2d198065ae3986547926cd2" ++
        "162f40a29f0c3c8745c0f50fba3852e5" ++ "66d44575c29d39a03f0cda721984b6f4" ++
        "40591f355e12d439ff150aab7613499d" ++ "bd49adabc8676eef023b15b65bfc5ca0" ++
        "6948109f23f350db82123535eb8a7433" ++ "bdabcb909271a6ecbcb58b936a88cd4e" ++
        "8f2e6ff5800175f113253d8fa9ca8885" ++ "c2f552e657dc603f252e1a8e308f76f0" ++
        "be79e2fb8f5d5fbbe2e30ecadd220723" ++ "c8c0aea8078cdfcb3868263ff8f09400" ++
        "54da48781893a7e49ad5aff4af300cd8" ++ "04a6b6279ab3ff3afb64491c85194aab" ++
        "760d58a606654f9f4400e8b38591356f" ++ "bf6425aca26dc85244259ff2b19c41b9" ++
        "f96f3ca9ec1dde434da7d2d392b905dd" ++ "f3d1f9af93d1af5950bd493f5aa731b4" ++
        "056df31bd267b6b90a079831aaf579be" ++ "0a39013137aac6d404f518cfd4684064" ++
        "7e78bfe706ca4cf5e9c5453e9f7cfd2b" ++ "8b4c8d169a44e55c88d4a9a7f9474241" ++
        "e221af44860018ab0856972e194cd934",
        "{s}",
        .{std.fmt.fmtSliceHexLower(encrypted.items)},
    );
    // zig fmt: on
}

/// takes encrypted header and payload, returns decrypted packet array list
/// header is from first byte to "length" field,
/// payload is remainder (includes packet number)
pub fn decryptPacket(
    comptime AesGcm: type,
    header: []const u8,
    payload: []const u8,
    key: [AesGcm.key_length]u8,
    iv: [AesGcm.nonce_length]u8,
    hp_key: [HP_KEY_LENGTH]u8,
    allocator: mem.Allocator,
) !std.ArrayList(u8) {
    // create header protection mask
    const Aes = switch (AesGcm) {
        std.crypto.aead.aes_gcm.Aes128Gcm => crypto.core.aes.Aes128,
        std.crypto.aead.aes_gcm.Aes256Gcm => crypto.core.aes.Aes256,
        else => @compileError("invalid AesGcm type"),
    };
    const sample = payload[4 .. 4 + 16];
    const mask = deriveHpMask(Aes, hp_key, sample.*);

    // create responce object
    var decrypted_res = std.ArrayList(u8).init(allocator);
    try decrypted_res.ensureTotalCapacityPrecise(
        header.len + payload.len - AesGcm.tag_length,
    );

    // unprotect first byte and derive packet number length
    try decrypted_res.appendSlice(header);
    decrypted_res.items[0] = header[0] ^ (mask[0] & 0x0f);
    const pn_length = @intCast(usize, decrypted_res.items[0] & 0x03) + 1;

    // unprotect packet number
    try decrypted_res.appendSlice(payload[0..pn_length]);
    var packet_number = decrypted_res.items[decrypted_res.items.len - pn_length ..];
    for (packet_number) |*val, idx| val.* ^= mask[1 + idx];

    // create nonce
    var nonce = [_]u8{0} ** AesGcm.nonce_length;
    mem.copy(u8, &nonce, &iv);
    for (nonce[nonce.len - pn_length ..]) |*val, idx| val.* ^= packet_number[idx];

    // decrypt payload
    const encrypted_payload = payload[pn_length .. payload.len - AesGcm.tag_length];
    const auth_tag = tag: {
        var dest = [_]u8{0} ** AesGcm.tag_length;
        mem.copy(u8, &dest, payload[payload.len - AesGcm.tag_length ..]);
        break :tag dest;
    };
    var decrypted_payload = try allocator.alloc(u8, encrypted_payload.len);
    defer allocator.free(decrypted_payload);
    try AesGcm.decrypt(
        decrypted_payload,
        encrypted_payload,
        auth_tag,
        decrypted_res.items,
        nonce,
        key,
    );
    try decrypted_res.appendSlice(decrypted_payload);

    return decrypted_res;
}

test "decryptPacket" {
    // test vectors from https://www.rfc-editor.org/rfc/rfc9001#name-server-initial
    var header = [_]u8{0} ** 18;
    _ = try std.fmt.hexToBytes(&header, "cf000000010008f067a5502a4262b5004075");
    var payload = [_]u8{0} ** 117;
    // zig fmt: off
    _ = try std.fmt.hexToBytes(
        &payload,
        "c0d95a482cd0991cd25b0aac406a" ++
        "5816b6394100f37a1c69797554780bb3" ++ "8cc5a99f5ede4cf73c3ec2493a1839b3" ++
        "dbcba3f6ea46c5b7684df3548e7ddeb9" ++ "c3bf9c73cc3f3bded74b562bfb19fb84" ++
        "022f8ef4cdd93795d77d06edbb7aaf2f" ++ "58891850abbdca3d20398c276456cbc4" ++
        "2158407dd074ee",
    );
    // zig fmt: on

    const initial_keys = tls.QuicKeys{
        .key = "\xcf\x3a\x53\x31\x65\x3c\x36\x4c\x88\xf0\xf3\x79\xb6\x06\x7e\x37".*,
        .iv = "\x0a\xc1\x49\x3c\xa1\x90\x58\x53\xb0\xbb\xa0\x3e".*,
        .hp = "\xc2\x06\xb8\xd9\xb9\xf0\xf3\x76\x44\x43\x0b\x49\x0e\xea\xa3\x14".*,
    };

    var decrypted = try decryptPacket(
        Aes128Gcm,
        &header,
        &payload,
        initial_keys.key,
        initial_keys.iv,
        initial_keys.hp,
        testing.allocator,
    );
    defer decrypted.deinit();

    // zig fmt: off
    try testing.expectFmt(
        "c1000000010008f067a5502a4262b50040750001" ++ // header (include packet number)
        "02000000000600405a020000560303ee" ++ "fce7f7b37ba1d1632e96677825ddf739" ++ // payload
        "88cfc79825df566dc5430b9a045a1200" ++ "130100002e00330024001d00209d3c94" ++
        "0d89690b84d08a60993c144eca684d10" ++ "81287c834d5311bcf32bb9da1a002b00" ++
        "020304",
        "{x}",
        .{std.fmt.fmtSliceHexLower(decrypted.items)},
    );
    // zig fmt: on
}

/// given header protection key and sample, return hp mask
pub fn deriveHpMask(
    comptime Aes: type,
    hp_key: [HP_KEY_LENGTH]u8,
    sample: [HP_KEY_LENGTH]u8,
) [HP_KEY_LENGTH]u8 {
    var mask: [HP_KEY_LENGTH]u8 = undefined;
    const ctx = Aes.initEnc(hp_key);
    ctx.encrypt(&mask, &sample);
    return mask;
}

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

    pub const MAX_TAG_LENGTH = math.max3(
        crypto.aead.aes_gcm.Aes128Gcm.tag_length,
        crypto.aead.aes_gcm.Aes256Gcm.tag_length,
        crypto.aead.chacha_poly.ChaCha20Poly1305.tag_length,
    );

    pub const MAX_NONCE_LENGTH = math.max3(
        crypto.aead.aes_gcm.Aes128Gcm.nonce_length,
        crypto.aead.aes_gcm.Aes256Gcm.nonce_length,
        crypto.aead.chacha_poly.ChaCha20Poly1305.nonce_length,
    );

    pub const MAX_KEY_LENGTH = math.max3(
        crypto.aead.aes_gcm.Aes128Gcm.key_length,
        crypto.aead.aes_gcm.Aes256Gcm.key_length,
        crypto.aead.chacha_poly.ChaCha20Poly1305.key_length,
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

    const instance_aes128gcm = _createComptime(crypto.aead.aes_gcm.Aes128Gcm);
    const instance_aes256gcm = _createComptime(crypto.aead.aes_gcm.Aes256Gcm);
    const instance_chacha20poly1305 = _createComptime(crypto.aead.chacha_poly.ChaCha20Poly1305);

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
            crypto.aead.aes_gcm.Aes128Gcm => .aes128gcm,
            crypto.aead.aes_gcm.Aes256Gcm => .aes256gcm,
            crypto.aead.chacha_poly.ChaCha20Poly1305 => .chacha20poly1305,
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
pub const QuicKeys2 = struct {
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

test "QuicKeys2" {
    const secret_hex = "c00cf151ca5be075ed0ebfb5c80323c4" ++ "2d6b7db67881289af4008f1f6c357aea";
    var secret = [_]u8{0} ** HkdfAbst.KEY_LENGTH;
    _ = try fmt.hexToBytes(&secret, secret_hex);
    const hkdf = HkdfAbst.get(.sha256);
    const aead = AeadAbst.get(.aes128gcm);
    const keys = QuicKeys2.deriveKeysFromSecret(secret, hkdf, aead);
    
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

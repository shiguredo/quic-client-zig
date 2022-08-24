const std = @import("std");
const crypto = std.crypto;
const testing = std.testing;

pub const Hmac = crypto.auth.hmac.sha2.HmacSha256;
pub const Hkdf = crypto.kdf.hkdf.HkdfSha256;

pub const INITIAL_SALT_V1 = [_]u8{
    0x38,
    0x76,
    0x2c,
    0xf7,
    0xf5,
    0x59,
    0x34,
    0xb3,
    0x4d,
    0x17,
    0x9a,
    0xe6,
    0xa4,
    0xc8,
    0x0c,
    0xad,
    0xcc,
    0xbb,
    0x7f,
    0x0a,
};

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

    const expected = [_]u8{
        0xb1,
        0x4b,
        0x91,
        0x81,
        0x24,
        0xfd,
        0xa5,
        0xc8,
        0xd7,
        0x98,
        0x47,
        0x60,
        0x2f,
        0xa3,
        0x52,
        0x0b,
    };

    try testing.expectEqual(expected, client_key);
}

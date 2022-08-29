const std = @import("std");
const testing = std.testing;

const q_crypto = @import("../crypto.zig");

const Hmac = q_crypto.Hmac;
const Hkdf = q_crypto.Hkdf;

pub const Provider = struct {
    initial_secret: [Hmac.key_length]u8 = undefined,
    client_initial: ?QuicKeys = null,
    server_initial: ?QuicKeys = null,

    const Self = @This();

    const Error = error{KeyNotInstalled};

    pub const QuicKeys = struct {
        secret: [Hmac.key_length]u8 = undefined,
        key: [QUIC_KEY_LENGTH]u8 = undefined,
        iv: [QUIC_IV_LENGTH]u8 = undefined,
        hp: [QUIC_HP_KEY_LENGTH]u8 = undefined,

        const QUIC_KEY_LENGTH = 16;
        const QUIC_IV_LENGTH = 12;
        const QUIC_HP_KEY_LENGTH = 16;
    };

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
};

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

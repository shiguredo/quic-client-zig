const std = @import("std");
const crypto = std.crypto;
const q_crypto = @import("crypto.zig");

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

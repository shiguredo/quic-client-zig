pub const Provider = @import("tls/provider.zig").Provider;

pub const TlsMessageType = @import("tls/tls_message.zig").TlsMessageType;
pub const TlsMessage = @import("tls/tls_message.zig").TlsMessage;

pub const HandshakeType = @import("tls/handshake.zig").HandshakeType;
pub const Handshake = @import("tls/handshake.zig").Handshake;

pub const ClientHello = @import("tls/client_server_hello.zig").ClientHello;
pub const ServerHello = @import("tls/client_server_hello.zig").ServerHello;

pub const extension = @import("tls/extension.zig");

pub const Epoch = enum {
    initial,
    zero_rtt,
    handshake,
    one_rtt,
};

const std = @import("std");

test {
    std.testing.refAllDecls(@This());
}

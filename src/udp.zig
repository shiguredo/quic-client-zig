const std = @import("std");
const net = std.net;
const os = std.os;
const testing = std.testing;
const builtin = @import("builtin");

const Datagram = net.Stream;

pub fn udpConnectToAddress(address: net.Address) !Datagram {
    const nonblock = if (std.io.is_async) os.SOCK.NONBLOCK else 0;
    const sock_flags = os.SOCK.DGRAM | nonblock |
        (if (builtin.target.os.tag == .windows) 0 else os.SOCK.CLOEXEC);
    const sockfd = try os.socket(address.any.family, sock_flags, os.IPPROTO.UDP);
    errdefer os.closeSocket(sockfd);

    if (std.io.is_async) {
        const loop = std.event.Loop.instance orelse return error.WouldBlock;
        try loop.connect(sockfd, &address.any, address.getOsSockLen());
    } else {
        try os.connect(sockfd, &address.any, address.getOsSockLen());
    }

    return Datagram{ .handle = sockfd };
}

// when you run this test, you have to run `test/udp_server.py`
test "udp send and recieve" {
    const address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 4000);
    var conn = try udpConnectToAddress(address);
    defer conn.close();
    _ = try conn.write("send test");
    var buf: [128]u8 = undefined;
    var n = try conn.read(&buf);
    try testing.expectEqualStrings("recieve test", buf[0..n]);
}

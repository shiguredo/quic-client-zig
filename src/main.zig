const std = @import("std");
const net = std.net;
const udp = @import("udp.zig");
const QuicSocket = @import("connection.zig").QuicSocket;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var allocator = gpa.allocator();

    var udp_sock = try udp.udpConnectToAddress(net.Address.initIp4(.{ 127, 0, 0, 1 }, 4433));
    var conn = try QuicSocket.init(
        udp_sock,
        allocator,
    );
    try conn.connect();

    var buf = [_]u8{0} ** 4096;
    while (true) {
        if (conn.isConnected()) break;
        const n = try udp_sock.read(&buf);
        try conn.recv(buf[0..n]);
    }
    defer conn.close();

    return;
}

test "all" {
    _ = @import("packet.zig");
    _ = @import("frame.zig");
    _ = @import("tls.zig");
    _ = @import("util.zig");
    _ = @import("connection.zig");
}

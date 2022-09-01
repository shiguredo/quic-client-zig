const std = @import("std");
const net = std.net;
const mem = std.mem;
const crypto = std.crypto;
const testing = std.testing;

const udp = @import("udp.zig");
const tls = @import("tls.zig");
const packet = @import("packet.zig");
const frame = @import("frame.zig");
const util = @import("util.zig");
const Buffer = @import("buffer.zig").Buffer;

pub const QuicConfig = struct {};

pub const QuicSocket = struct {
    tls_provider: tls.Provider,
    dg_socket: udp.DatagramSocket,

    const Self = @This();

    pub fn init(address: net.Address) !Self {
        var dg_socket = try udp.udpConnectToAddress(address);
        return .{
            .tls_provider = tls.Provider{},
            .dg_socket = dg_socket,
        };
    }

    pub fn connnect(self: *Self, allocator: mem.Allocator) !void {
        const scid = scid: {
            var id = try packet.ConnectionId.init(8);
            crypto.random.bytes(id.slice());
            break :scid id;
        };
        const dcid = dcid: {
            var id = try packet.ConnectionId.init(8);
            crypto.random.bytes(id.slice());
            break :dcid id;
        };

        // setup tls
        self.tls_provider.setUpInitial(dcid.constSlice());
        self.tls_provider.x25519_keypair = try crypto.dh.X25519.KeyPair.create(null);

        var c_hello_frame = ch: {
            var c_hello = try self.tls_provider.createClientHello(allocator, scid);
            defer c_hello.deinit();
            var ch_frame = frame.CryptoFrame{
                .offset = try util.VariableLengthInt.fromInt(0),
                .data = data: {
                    var data = std.ArrayList(u8).init(allocator);
                    try c_hello.encode(data.writer());
                    break :data data;
                },
            };
            break :ch ch_frame;
        };
        defer c_hello_frame.deinit();

        var ip = packet.InitialPacket{
            .pn_length = 0x00,
            .dst_cid = dcid,
            .src_cid = scid,
            .token = std.ArrayList(u8).init(allocator),
            .packet_number = 0x00,
            .payload = p: {
                var frames = std.ArrayList(frame.Frame).init(allocator);
                try frames.append(.{ .crypto = c_hello_frame });
                break :p frames;
            },
        };
        defer ip.deinit();

        var buf = Buffer(65536).init();
        try ip.encodeEncrypted(buf.writer(), allocator, self.tls_provider);
        _ = try self.dg_socket.write(buf.getUnreadSlice());
    }
};

test "connect()" {
    var sock = try QuicSocket.init(net.Address.initIp4(.{ 127, 0, 0, 1 }, 4433));
    try sock.connnect(testing.allocator);
}

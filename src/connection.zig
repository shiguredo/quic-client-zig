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

    pub fn close(self: *Self) void {
        self.tls_provider.deinit();
        self.dg_socket.close();
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

        var c_initial = packet.LongHeaderPacket{
            .flags = packet.LongHeaderFlags.initial(1),
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
        defer c_initial.deinit();

        var w_buf = Buffer(65536).init();
        try c_initial.encodeEncrypted(w_buf.writer(), allocator, self.tls_provider);
        _ = try self.dg_socket.write(w_buf.getUnreadSlice());

        var r_buf = [_]u8{0} ** 65536;
        var count: usize = 0;
        while (count == 0) : (count += try self.dg_socket.reader().read(r_buf[count..])) {}
        var stream = std.io.fixedBufferStream(r_buf[0..count]);

        var s_initial = try packet.LongHeaderPacket.decodeEncrypted(
            stream.reader(),
            allocator,
            self.tls_provider,
        );
        defer s_initial.deinit();

        for (s_initial.payload.items) |f| {
            switch (f) {
                .crypto => |c| try self.tls_provider.handleServerHello(c.data.items, allocator),
                else => {},
            }
        }

        self.tls_provider.setUpEarly(null);
        try self.tls_provider.createSharedKey();
        try self.tls_provider.setUpHandshake(allocator);

        var s_handshake = try packet.LongHeaderPacket.decodeEncrypted(
            stream.reader(),
            allocator,
            self.tls_provider,
        );
        defer s_handshake.deinit();

        var c_initial_2 = packet.LongHeaderPacket{
            .flags = packet.LongHeaderFlags.initial(1),
            .dst_cid = dcid,
            .src_cid = scid,
            .token = std.ArrayList(u8).init(allocator),
            .packet_number = 0x01,
            .payload = p: {
                var frames = std.ArrayList(frame.Frame).init(allocator);
                const ack_frame = frame.AckFrame{
                    .largest_ack = try util.VariableLengthInt.fromInt(0),
                    .ack_delay = try util.VariableLengthInt.fromInt(400),
                    .first_ack_range = try util.VariableLengthInt.fromInt(0),
                    .ack_ranges = std.ArrayList(frame.AckFrame.AckRange).init(allocator),
                };
                try frames.append(.{ .ack = ack_frame });
                break :p frames;
            },
        };
        defer c_initial_2.deinit();

        w_buf.clear();
        try c_initial_2.encodeEncrypted(w_buf.writer(), allocator, self.tls_provider);
        _ = try self.dg_socket.write(w_buf.getUnreadSlice());
    }
};

test "connect()" {
    // To run this test, set QUIC_CONNECTION_TEST_ENABLED=1
    if (std.os.getenv("QUIC_CONNECTION_TEST_ENABLED")) |_| {} else return error.SkipZigTest;

    var sock = try QuicSocket.init(net.Address.initIp4(.{ 127, 0, 0, 1 }, 4433));
    defer sock.close();
    try sock.connnect(testing.allocator);
}

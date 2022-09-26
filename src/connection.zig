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
const stream = @import("stream.zig");
const Buffer = @import("buffer.zig").Buffer;
const RangeSet = @import("range_set.zig").RangeSet;

pub const QuicConfig = struct {};

pub const QuicSocket = struct {
    tls_provider: tls.Provider,
    dg_socket: udp.DatagramSocket,
    c_streams: stream.CryptoStreams,
    ack_ranges: RangeSet,
    allocator: mem.Allocator,

    const Self = @This();

    pub fn init(address: net.Address, allocator: mem.Allocator) !Self {
        var dg_socket = try udp.udpConnectToAddress(address);

        return .{
            .tls_provider = tls.Provider{},
            .dg_socket = dg_socket,
            .c_streams = stream.CryptoStreams.init(allocator),
            .ack_ranges = RangeSet.init(allocator),
            .allocator = allocator,
        };
    }

    pub fn close(self: *Self) void {
        self.tls_provider.deinit();
        self.dg_socket.close();
    }

    /// Start handshake
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

        var w_buf = Buffer(4096).init();
        try c_initial.encodeEncrypted(w_buf.writer(), allocator, self.tls_provider);
        _ = try self.dg_socket.write(w_buf.getUnreadSlice());
    }

    /// recieve data from udp socket and handle it.
    pub fn recv(self: *Self, buf: []const u8) !void {
        var s = std.io.fixedBufferStream(buf);

        while (packet.LongHeaderPacket.decodeEncrypted(
            s.reader(),
            self.allocator,
            self.tls_provider,
        )) |pkt| {
            self.handlePacket(pkt);
        } else |err| {
            if (err != error.EndOfStream) return err;
        }
    }

    /// transmit data if needed (TODO: implementation)
    pub fn transmit(self: *Self) !void {
        _ = self;
    }

    pub fn handlePacket(self: *Self, pkt: packet.LongHeaderPacket) !void {
        for (pkt.payload) |frm| {
            switch (frm) {
                .padding => {},
                .ack => {},
                .crypto => |f| self.handleCryptoFrame(f),
                .stream => {},
                .handshake_done => {},
            }
        }
        try self.ack_ranges.addOne(@intCast(u64, pkt.packet_number));
    }

    pub fn handleCryptoFrame(self: *Self, c_frame: frame.CryptoFrame, epoch: tls.Epoch) !void {
        var s = self.c_streams.getPtr(epoch);
        const data = c_frame.data.items;
        const offset = c_frame.offset;
        const end_offset = offset + data.len;

        mem.copy(u8, s.*.items[offset..end_offset], data);
    }
};

test "connect()" {
    // To run this test, set QUIC_CONNECTION_TEST_ENABLED=1
    if (std.os.getenv("QUIC_CONNECTION_TEST_ENABLED")) |_| {} else return error.SkipZigTest;

    var sock = try QuicSocket.init(
        net.Address.initIp4(.{ 127, 0, 0, 1 }, 4433),
        testing.allocator,
    );
    defer sock.close();
    try sock.connnect(testing.allocator);
}

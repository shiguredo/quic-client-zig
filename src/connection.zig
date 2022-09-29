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

const MAX_CID_LENGTH = 255;
pub const ConnectionId = std.BoundedArray(u8, MAX_CID_LENGTH);

pub const QuicSocket = struct {
    tls_provider: tls.Provider,
    dg_socket: udp.DatagramSocket,
    c_streams: stream.CryptoStreams,
    ack_ranges: RangeSet,

    dcid: ConnectionId,
    scid: ConnectionId,

    allocator: mem.Allocator,

    const Self = @This();

    pub fn init(udp_sock: udp.DatagramSocket, allocator: mem.Allocator) !Self {
        const scid = scid: {
            var id = try ConnectionId.init(8);
            crypto.random.bytes(id.slice());
            break :scid id;
        };
        const dcid = dcid: {
            var id = try ConnectionId.init(8);
            crypto.random.bytes(id.slice());
            break :dcid id;
        };

        return .{
            .tls_provider = try tls.Provider.init(allocator, dcid.constSlice()),
            .dg_socket = udp_sock,
            .c_streams = stream.CryptoStreams.init(allocator),
            .ack_ranges = RangeSet.init(allocator),
            .dcid = dcid,
            .scid = scid,
            .allocator = allocator,
        };
    }

    pub fn close(self: *Self) void {
        self.tls_provider.deinit();
        self.dg_socket.close();
    }

    /// Start handshake
    pub fn connnect(self: *Self) !void {
        var c_hello_frame = ch: {
            var c_hello = try self.tls_provider.createClientHello(self.scid);
            defer c_hello.deinit();
            var ch_frame = frame.CryptoFrame{
                .offset = try util.VariableLengthInt.fromInt(0),
                .data = data: {
                    var data = std.ArrayList(u8).init(self.allocator);
                    try c_hello.encode(data.writer());
                    break :data data;
                },
            };
            break :ch ch_frame;
        };

        var c_initial = packet.LongHeaderPacket{
            .flags = packet.LongHeaderFlags.initial(1),
            .dst_cid = self.dcid,
            .src_cid = self.scid,
            .token = std.ArrayList(u8).init(self.allocator),
            .packet_number = 0x00,
            .payload = p: {
                var frames = std.ArrayList(frame.Frame).init(self.allocator);
                try frames.append(.{ .crypto = c_hello_frame });
                break :p frames;
            },
        };
        defer c_initial.deinit();

        var w_buf = Buffer(4096).init();
        try c_initial.encodeEncrypted(
            w_buf.writer(),
            self.allocator,
            self.tls_provider,
        );
        _ = try self.dg_socket.write(w_buf.getUnreadSlice());
    }

    pub fn isConnected(self: Self) bool {
        // TODO: implement
        _ = self;
        return false;
    }

    // prvate functions below

    /// recieve data from udp socket and handle it.
    pub fn recv(self: *Self, buf: []const u8) !void {
        var s = std.io.fixedBufferStream(buf);

        while (packet.LongHeaderPacket.decodeEncrypted(
            s.reader(),
            self.allocator,
            self.tls_provider,
        )) |pkt| {
            try self.handlePacket(pkt);
        } else |err| {
            if (err != error.EndOfStream) return err;
        }
    }

    /// transmit data if needed (TODO: implementation)
    fn transmit(self: *Self) !void {
        _ = self;
    }

    fn handlePacket(self: *Self, pkt: packet.LongHeaderPacket) !void {
        const epoch = pkt.flags.packet_type.toEpoch();
        for (pkt.payload.items) |frm| {
            switch (frm) {
                .padding => {},
                .ack => {},
                .crypto => |f| {
                    if (epoch == .no_crypto) return error.ProtocolViolation;
                    try self.handleCryptoFrame(f, epoch);
                },
                .stream => {},
                .handshake_done => {},
            }
        }
        try self.ack_ranges.addOne(@intCast(u64, pkt.packet_number));
        try self.transmit();
    }

    fn handleCryptoFrame(self: *Self, c_frame: frame.CryptoFrame, epoch: tls.Epoch) !void {
        var cs = self.c_streams.getPtr(epoch);
        try cs.reciever.push(
            c_frame.data.items,
            @intCast(usize, c_frame.offset.value),
        );
        try self.tls_provider.handleStream(cs);
    }
};

test "connect()" {
    // To run this test, set QUIC_CONNECTION_TEST_ENABLED=1
    if (std.os.getenv("QUIC_CONNECTION_TEST_ENABLED")) |_| {} else return error.SkipZigTest;

    var udp_sock = try udp.udpConnectToAddress(net.Address.initIp4(.{ 127, 0, 0, 1 }, 4433));
    var conn = try QuicSocket.init(
        udp_sock,
        testing.allocator,
    );

    var buf = [_]u8{0} ** 4096;
    while (true) {
        if (conn.isConnected()) break;
        const n = try udp_sock.read(&buf);
        try conn.recv(buf[0..n]);
    }
    defer conn.close();
    try conn.connnect();
}

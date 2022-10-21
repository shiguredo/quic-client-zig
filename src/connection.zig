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
const Spaces = @import("number_space.zig").Spaces;

pub const QuicConfig = struct {};

const RBUF_MAX_LEN = 4096;
pub const ConnectionId = struct {
    id: Id,

    const Self = @This();
    pub const Id = std.BoundedArray(u8, CID_CAPACITY);
    const MAX_CID_LENGTH = 20;
    const CID_CAPACITY = 255;

    pub fn fromSlice(id: []const u8) Self {
        return .{
            .id = Id.fromSlice(id) catch unreachable,
        };
    }

    /// the size must be shorter than or equal to CID_CAPACITY (= 255)
    pub fn initRandom(size: usize) Self {
        return .{
            .id = id: {
                var id = Id.init(size) catch unreachable;
                crypto.random.bytes(id.slice());
                break :id id;
            },
        };
    }

    pub fn encode(self: Self, writer: anytype) !void {
        try writer.writeIntBig(@intCast(u8, self.id.len));
        try writer.writeAll(self.id.constSlice());
    }

    pub fn decode(reader: Self) !Self {
        const len = try reader.readIntBig(u8);
        return .{
            .id = id: {
                var id = Id.init(@intCast(usize, len)) catch unreachable;
                try reader.readNoEof(id.slice());
                break :id id;
            },
        };
    }
};

const ConnectionState = enum {
    first_flight,
    connected,
};

pub const QuicSocket = struct {
    state: ConnectionState = .first_flight,
    tls_provider: tls.Provider,
    dg_socket: udp.DatagramSocket,
    c_streams: stream.CryptoStreams,

    dcid: ConnectionId,
    scid: ConnectionId,

    spaces: Spaces,

    pkt_buf: std.ArrayList(packet.Packet),

    allocator: mem.Allocator,

    const Self = @This();

    pub fn init(udp_sock: udp.DatagramSocket, allocator: mem.Allocator) !Self {
        const scid = ConnectionId.initRandom(8);
        const dcid = ConnectionId.initRandom(8);

        return Self{
            .tls_provider = try tls.Provider.init(allocator),
            .dg_socket = udp_sock,
            .c_streams = stream.CryptoStreams.init(allocator),
            .dcid = dcid,
            .scid = scid,
            .spaces = Spaces.init(allocator),
            .pkt_buf = std.ArrayList(packet.Packet).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn close(self: *Self) void {
        self.tls_provider.deinit();
        self.dg_socket.close();
        self.c_streams.deinit();
        self.spaces.deinit();
        self.pkt_buf.deinit();
    }

    /// Start handshake
    pub fn connect(self: *Self) !void {
        var initial_stream = self.c_streams.getPtr(.initial);
        try self.tls_provider.initiateHandshake(
            initial_stream,
            self.dcid,
            self.scid,
        );

        try self.buildPacket(.initial);
        try self.transmit();
    }

    pub fn isConnected(self: Self) bool {
        return self.state == .connected;
    }

    /// recieve data from udp socket and handle it.
    pub fn recv(self: *Self, buf: []const u8) !void {
        var s = std.io.fixedBufferStream(buf);

        while (packet.Packet.decodeEncrypted(
            s.reader(),
            self.allocator,
            self.tls_provider,
        )) |pkt| {
            try self.handlePacket(pkt);
        } else |err| {
            if (err != error.EndOfStream) return err;
        }
        try self.transmit();
    }

    // prvate functions below

    /// transmit data if needed
    fn transmit(self: *Self) !void {
        var buf = Buffer(RBUF_MAX_LEN).init();
        for (self.pkt_buf.items) |*pkt| {
            try pkt.encodeEncrypted(
                buf.writer(),
                self.allocator,
                self.tls_provider,
            );
            pkt.deinit();
        }
        self.pkt_buf.clearRetainingCapacity();
        _ = try self.dg_socket.write(buf.getUnreadSlice());
    }

    fn handlePacket(self: *Self, pkt: packet.Packet) !void {
        if (self.state == .first_flight) {
            self.dcid = pkt.src_cid;
        }
        const epoch = pkt.flags.packetType().toEpoch();
        var space = self.spaces.s.getPtr(pkt.flags.packetType().toSpace());
        try space.ack_ranges.addOne(@intCast(u64, pkt.packet_number));
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
    }

    fn handleCryptoFrame(self: *Self, c_frame: frame.CryptoFrame, epoch: tls.Epoch) !void {
        var cs = self.c_streams.getPtr(epoch);
        try cs.reciever.push(
            c_frame.data,
            @intCast(usize, c_frame.offset.value),
        );
        try self.tls_provider.handleStream(cs);
        if (epoch == .handshake) {
            try self.buildPacket(.initial);
            try self.buildPacket(.handshake);
        }
        if (self.tls_provider.state == .connected) {
            self.state = .connected;
        }
    }

    /// build packet and push it queue if needed.
    fn buildPacket(self: *Self, packet_type: packet.PacketTypes) !void {
        var pkt = switch (packet_type) {
            .initial => try self.buildInitial(),
            .handshake => try self.buildHandshake(),
            else => return error.Unimplemented,
        };

        // append crypto frame
        switch (packet_type) {
            .initial, .handshake => try self.addCryptoFrames(&pkt),
            else => {},
        }

        // append ack frame
        // TODO: calc ack delay
        const space_enum = packet_type.toSpace();
        var space = self.spaces.s.getPtr(space_enum);
        var ack_frame = try frame.AckFrame.fromRangeSet(space.ack_ranges, 0, self.allocator);
        if (ack_frame) |a| {
            try pkt.payload.append(.{ .ack = a });
        }

        // if payload length is shorter than 20, encryptPacket will fail, so add padding.
        // TODO: remove this padding
        try pkt.payload.append(.{ .padding = .{ .length = 20 } });

        try self.pkt_buf.append(pkt);
        return;
    }

    fn buildInitial(self: *Self) !packet.Packet {
        var number_space = self.spaces.s.getPtr(.initial);
        const flags = packet.LongHeaderFlags{
            .pn_length = 0b11,
            .packet_type = .initial,
        };
        return .{
            .flags = packet.Flags{ .long = flags },
            .dst_cid = self.dcid,
            .src_cid = self.scid,
            .token = std.ArrayList(u8).init(self.allocator),
            .packet_number = @intCast(u32, number_space.generate()),
            .payload = std.ArrayList(frame.Frame).init(self.allocator),
        };
    }

    fn buildHandshake(self: *Self) !packet.Packet {
        var number_space = self.spaces.s.getPtr(.handshake);
        const flags = packet.LongHeaderFlags{
            .pn_length = 0b11,
            .packet_type = .handshake,
        };
        return .{
            .flags = packet.Flags{ .long = flags },
            .dst_cid = self.dcid,
            .src_cid = self.scid,
            .token = null,
            .packet_number = @intCast(u32, number_space.generate()),
            .payload = std.ArrayList(frame.Frame).init(self.allocator),
        };
    }

    /// add crypto frame to given packet
    /// packet type is must be initial or handshake
    fn addCryptoFrames(self: *Self, pkt: *packet.Packet) !void {
        const epoch = pkt.flags.packetType().toEpoch();
        var s = self.c_streams.getPtr(epoch);

        while (try s.sender.emit(RBUF_MAX_LEN, self.allocator)) |rbuf| {
            var c = try frame.CryptoFrame.fromRangeBuf(rbuf, self.allocator);
            try pkt.payload.append(.{ .crypto = c });
        }
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
    defer conn.close();
    try conn.connect();

    var buf = [_]u8{0} ** 4096;
    while (true) {
        if (conn.isConnected()) break;
        const n = try udp_sock.read(&buf);
        try conn.recv(buf[0..n]);
    }
}

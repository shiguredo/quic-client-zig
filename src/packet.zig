const std = @import("std");
const crypto = std.crypto;
const aes_gcm = crypto.aead.aes_gcm;
const mem = std.mem;
const testing = std.testing;

const connection = @import("connection.zig");
const util = @import("util.zig");
const frame = @import("frame.zig");
const tls = @import("tls.zig");
const q_crypto = @import("crypto.zig");
const Stream = @import("stream.zig").Stream;
const VariableLengthInt = util.VariableLengthInt;
const SpacesEnum = @import("number_space.zig").SpacesEnum;

const HeaderForm = enum(u1) {
    short = 0b0,
    long = 0b1,
};

pub const PacketTypes = enum {
    initial,
    zero_rtt,
    handshake,
    retry,
    version_nego,
    one_rtt,

    const Self = @This();

    pub fn toSpace(self: Self) SpacesEnum {
        return switch (self) {
            .initial => .initial,
            .handshake => .handshake,
            .zero_rtt, .one_rtt => .application,
            else => unreachable, // TODO: error handling for no packet number space
        };
    }

    pub fn toEpoch(self: Self) tls.Epoch {
        return switch (self) {
            .initial => .initial,
            .zero_rtt => .zero_rtt,
            .handshake => .handshake,
            else => .no_crypto,
        };
    }
};

pub const LongHeaderPacketTypes = enum(u2) {
    initial = 0x00,
    zero_rtt = 0x01,
    handshake = 0x02,
    retry = 0x03,
};

pub const LongHeaderFlags = packed struct {
    pn_length: u2,
    reserved: u2 = 0b00,
    packet_type: LongHeaderPacketTypes,
    fixed_bit: u1 = 0b1,
    header_form: HeaderForm = .long,

    const Self = @This();

    pub fn initial(pn_length: usize) Self {
        return .{
            .pn_length = switch (pn_length) {
                1...4 => @intCast(u2, pn_length - 1),
                else => unreachable,
            },
            .packet_type = .initial,
        };
    }

    pub fn toU8(self: Self) u8 {
        return @bitCast(u8, self);
    }

    pub fn fromU8(flags_byte: u8) Self {
        const flags = @bitCast(Self, flags_byte);
        return flags;
    }

    test "convert initial packet flags to u8" {
        const flags = Self{
            .pn_length = 0b10,
            .packet_type = .initial,
        };
        try testing.expectEqual(@as(u8, 0b11000010), flags.toU8());
        const flags2 = Self.fromU8(0b11000001);
        try testing.expectEqual(@as(u2, 0b01), flags2.pn_length);
    }
};

pub const ShortHeaderFlags = packed struct {
    pn_length: u2,
    key_phase: u1,
    reserved: u2,
    spin: u1,
    fixed: u1 = 0b1,
    header_form: HeaderForm = .short,

    const Self = @This();

    pub fn toU8(self: Self) u8 {
        return @bitCast(u8, self);
    }

    pub fn fromU8(byte: u8) Self {
        return @bitCast(Self, byte);
    }
};

pub const Flags = union(HeaderForm) {
    short: ShortHeaderFlags,
    long: LongHeaderFlags,

    const Self = @This();

    pub fn toU8(self: Self) u8 {
        return switch (self) {
            .short => |s| s.toU8(),
            .long => |l| l.toU8(),
        };
    }

    pub fn fromU8(byte: u8) Self {
        const form_bit = byte & 0x80;
        if (form_bit == 0) {
            return .{ .short = ShortHeaderFlags.fromU8(byte) };
        } else {
            return .{ .long = LongHeaderFlags.fromU8(byte) };
        }
    }

    pub fn packetType(self: Self) PacketTypes {
        if (@as(HeaderForm, self) == .short) {
            return .one_rtt;
        } else {
            return switch (self.long.packet_type) {
                .initial => .initial,
                .handshake => .handshake,
                .zero_rtt => .zero_rtt,
                .retry => .retry,
            };
        }
    }

    pub fn rawPnLength(self: Self) u2 {
        return switch (self) {
            .long => |l| l.pn_length,
            .short => |s| s.pn_length,
        };
    }

    pub fn pnLength(self: Self) usize {
        return @intCast(usize, self.rawPnLength()) + 1;
    }
};

const MIN_UDP_PAYLOAD_LENGTH = 1200;
const ConnectionId = connection.ConnectionId;

pub const QUIC_VERSION_1 = 0x00000001;

/// TODO: support 1-RTT packet and rename LongHeaderPacket -> Packet
pub const LongHeaderPacket = struct {
    flags: Flags,

    version: u32 = QUIC_VERSION_1,
    dst_cid: ConnectionId,
    src_cid: ConnectionId,
    token: ?std.ArrayList(u8), // only for Initial Packet
    packet_number: u32,

    payload: std.ArrayList(frame.Frame),

    const Self = @This();

    pub const Error = error{
        InvalidHeaderFormat,
    };

    pub fn deinit(self: Self) void {
        if (self.token) |token| token.deinit();
        for (self.payload.items) |*f| f.deinit();
        self.payload.deinit();
    }

    pub fn encodeEncrypted(
        self: *const Self,
        writer: anytype,
        allocator: mem.Allocator,
        tls_provider: tls.Provider,
    ) !void {
        const packet_type = self.flags.packetType();

        // make plain text payload array
        // plain text is (packet number) + (frame payloads) + (padding)
        var plain_text = std.ArrayList(u8).init(allocator);
        defer plain_text.deinit();

        for (self.payload.items) |*frame_item| {
            try frame_item.encode(plain_text.writer());
        }

        if (packet_type == .initial) {
            // Client initial packet's UDP payload size must be 1200 bytes or larger.
            // add padding to meet this constraint
            const len_without_length_field = blk: { // calculate for initial packet
                var temp: usize = 0;
                temp += try self.headerLengthWithoutLengthField();
                temp += plain_text.items.len;
                break :blk temp;
            };
            if (len_without_length_field + 2 < MIN_UDP_PAYLOAD_LENGTH) {
                // if UDP payload less than 1200, add padding
                // + 2 is the min length of "length" field
                const padding_len = MIN_UDP_PAYLOAD_LENGTH - len_without_length_field;
                const padding = frame.PaddingFrame.init(padding_len);
                try padding.encode(plain_text.writer());
            }
        }

        // create header
        const length_field = plain_text.items.len + self.flags.pnLength() + aes_gcm.Aes128Gcm.tag_length;
        const rem_length = try VariableLengthInt.fromInt(length_field);
        var pn_array = [_]u8{0} ** @sizeOf(u32);
        mem.writeIntBig(u32, &pn_array, self.packet_number);

        var header = std.ArrayList(u8).init(allocator);
        defer header.deinit();
        var h_writer = header.writer();
        try h_writer.writeIntBig(u8, self.firstByte());
        try h_writer.writeIntBig(u32, QUIC_VERSION_1);
        try h_writer.writeIntBig(u8, @intCast(u8, self.dst_cid.len));
        try h_writer.writeAll(self.dst_cid.constSlice());
        try h_writer.writeIntBig(u8, @intCast(u8, self.src_cid.len));
        try h_writer.writeAll(self.src_cid.constSlice());
        if (packet_type == .initial) {
            // token field appears only in Initial packet
            const token_length = (try self.tokenLengthVlInt()).?;
            try token_length.encode(h_writer);
            try h_writer.writeAll(self.token.?.items);
        }
        try rem_length.encode(h_writer);
        try h_writer.writeAll(pn_array[pn_array.len - self.flags.pnLength() ..]);

        const keys = switch (packet_type) {
            .initial => tls_provider.client_initial orelse return tls.Provider.Error.KeyNotInstalled,
            .handshake => tls_provider.client_handshake orelse return tls.Provider.Error.KeyNotInstalled,
            else => tls_provider.server_master orelse return tls.Provider.Error.KeyNotInstalled,
        };

        // encrypt
        const encrypted_bytes = try q_crypto.encryptPacket(
            aes_gcm.Aes128Gcm,
            header.items,
            plain_text.items,
            keys.key,
            keys.iv,
            keys.hp,
            allocator,
        );
        defer encrypted_bytes.deinit();

        // write to writer
        try writer.writeAll(encrypted_bytes.items);
        return;
    }

    pub fn decodeEncrypted(
        reader: anytype,
        allocator: mem.Allocator,
        tls_provider: tls.Provider,
    ) !Self {
        // to save header bytes, using SaveHistoryStream
        var h_stream = util.saveHistoryStream(reader, allocator);
        defer h_stream.deinit();
        var h_reader = h_stream.reader();

        // read header
        const packet_type = packet_type: {
            const protected_flags =
                Flags.fromU8(try h_reader.readIntBig(u8));
            break :packet_type protected_flags.packetType();
        };
        const version = try h_reader.readIntBig(u32);
        const dcid_length = try h_reader.readIntBig(u8);
        var dcid = try ConnectionId.init(@intCast(usize, dcid_length));
        try h_reader.readNoEof(dcid.slice());
        const scid_length = try h_reader.readIntBig(u8);
        var scid = try ConnectionId.init(@intCast(usize, scid_length));
        try h_reader.readNoEof(scid.slice());
        const token_length =
            if (packet_type == .initial) try VariableLengthInt.decode(h_reader) else null;
        const token = if (packet_type == .initial) token: {
            var temp = std.ArrayList(u8).init(allocator);
            try temp.resize(@intCast(usize, token_length.?.value));
            try h_reader.readNoEof(temp.items);
            break :token temp;
        } else null;
        const length = try VariableLengthInt.decode(h_reader);

        // get what is read as header bytes
        const header_bytes = h_stream.history();
        const pn_offset = header_bytes.len;

        // read encrypted payload
        // after now, use normal reader instead
        const encrypted_payload = payload: {
            var buf = try allocator.alloc(u8, @intCast(usize, length.value));
            try reader.readNoEof(buf);
            break :payload buf;
        };
        defer allocator.free(encrypted_payload);

        // because this is client, use server initial keys to decrypt recieved packet
        const keys = switch (packet_type) {
            .initial => tls_provider.server_initial orelse return tls.Provider.Error.KeyNotInstalled,
            .handshake => tls_provider.server_handshake orelse return tls.Provider.Error.KeyNotInstalled,
            else => unreachable,
        };

        const decrypted_packet = try q_crypto.decryptPacket(
            aes_gcm.Aes128Gcm,
            header_bytes,
            encrypted_payload,
            keys.key,
            keys.iv,
            keys.hp,
            allocator,
        );
        defer decrypted_packet.deinit();

        // get unprotected first byte and packet number
        const first_byte = Flags.fromU8(decrypted_packet.items[0]);
        const pn_length_decoded = first_byte.pnLength();
        const p_number = pn: {
            var pn_array = [_]u8{0} ** @sizeOf(u32);
            mem.copy(
                u8,
                pn_array[@sizeOf(u32) - pn_length_decoded ..],
                decrypted_packet.items[pn_offset .. pn_offset + pn_length_decoded],
            );
            break :pn mem.readIntBig(u32, &pn_array);
        };

        const payload = payload: {
            const bytes = decrypted_packet.items[pn_offset + pn_length_decoded ..];
            var payload = std.ArrayList(frame.Frame).init(allocator);
            var stream = std.io.fixedBufferStream(bytes);
            var s_reader = stream.reader();
            while (frame.Frame.decode(s_reader, allocator)) |fr|
                try payload.append(fr)
            else |err| if (err != error.EndOfStream) return err;
            break :payload payload;
        };

        return Self{
            .flags = first_byte,
            .version = version,
            .dst_cid = dcid,
            .src_cid = scid,
            .token = token,
            .packet_number = p_number,
            .payload = payload,
        };
    }

    /// get payload encoded length without padding field
    fn payloadByteLength(self: *const Self) usize {
        var len: usize = 0;
        for (self.payload.items) |*frame_item| {
            len += frame_item.getEncLen();
        }
        return len;
    }

    /// return first byte as u8
    pub fn firstByte(self: *const Self) u8 {
        return self.flags.toU8();
    }

    /// return token length in VariableLengthInt struct
    fn tokenLengthVlInt(
        self: *const Self,
    ) VariableLengthInt.Error!?VariableLengthInt {
        return if (self.token) |token|
            try VariableLengthInt.fromInt(token.items.len)
        else
            null;
    }

    /// return (header without "length" field length) + (not padded payload length)
    fn headerLengthWithoutLengthField(self: *const Self) !usize {
        var ret: usize = 0;
        ret += 7; // first byte + version field + dcid len field + scid len field
        ret += self.dst_cid.len;
        ret += self.src_cid.len;
        ret += if (self.token) |token| token_field: {
            var temp: usize = 0;
            const token_length = (try self.tokenLengthVlInt()).?;
            temp += token_length.len;
            temp += token.items.len;
            break :token_field temp;
        } else 0;
        ret += self.flags.pnLength();
        return ret;
    }
};

test "decode initial packet" {
    var server_initial = [_]u8{0} ** 144;
    // zig fmt: off
    _ = try std.fmt.hexToBytes(
        &server_initial,
        "c00000000108545c86fd3cefe8230882" ++ "b24f07a52dd4cd0040761477113507c9" ++
        "796b2535d841c5afa1017723249e4912" ++ "b7fe609b92054a79370035c31997b0d9" ++
        "26778e5a131901dc4ca1c0b17d42fffb" ++ "1e27aee9bfdf4835be12d07e53488031" ++
        "6abfdf00c37dc48fff8a3520b3deb41b" ++ "a6e7823c915aea1e6ebb3a9adc1d48d8" ++
        "2e0a742ea46eba7061d772a6bf2a359c",
    );
    // zig fmt: on
    var stream = std.io.fixedBufferStream(&server_initial);
    var tls_provider = try tls.Provider.init(testing.allocator);
    defer tls_provider.deinit();

    var dummy_stream = Stream.init(testing.allocator);
    defer dummy_stream.deinit();

    var c_dcid = try connection.ConnectionId.fromSlice("\x76\x49\x73\x32\xb6\x4c\x00\x9c");
    var c_scid = try connection.ConnectionId.fromSlice("\x00");
    try tls_provider.initiateHandshake(&dummy_stream, c_dcid, c_scid);

    var initial_packet = try LongHeaderPacket.decodeEncrypted(stream.reader(), testing.allocator, tls_provider);
    defer initial_packet.deinit();

    try testing.expectEqual(@as(u2, 0b01), initial_packet.flags.rawPnLength());
    try testing.expectEqual(@as(u32, 0x01), initial_packet.version);
    try testing.expectEqualSlices(
        u8,
        "\x54\x5c\x86\xfd\x3c\xef\xe8\x23",
        initial_packet.dst_cid.constSlice(),
    );
    try testing.expectEqualSlices(u8, "\x82\xb2\x4f\x07\xa5\x2d\xd4\xcd", initial_packet.src_cid.constSlice());
    try testing.expectEqual(@as(u32, 0x00), initial_packet.packet_number);

    try testing.expectEqual(
        frame.FrameTypes.ack,
        @as(frame.FrameTypes, initial_packet.payload.items[0]),
    );
    try testing.expectEqual(
        frame.FrameTypes.crypto,
        @as(frame.FrameTypes, initial_packet.payload.items[1]),
    );
    // zig fmt: off
    try testing.expectFmt(
        "020000560303165efaaecd6bf8dfd822" ++ "63c401ee4cb8abca9d61640e195fc9b1" ++
        "67904904c60a00130100002e002b0002" ++ "030400330024001d0020416e6d420521" ++
        "e12d8592c00d334c16749542222edd7f" ++ "62accc1cb16b5f3fb300",
        "{x}",
        .{std.fmt.fmtSliceHexLower(initial_packet.payload.items[1].crypto.data)},
    );
    // zig fmt: on
}

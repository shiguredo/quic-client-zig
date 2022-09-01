const std = @import("std");
const crypto = std.crypto;
const aes_gcm = crypto.aead.aes_gcm;
const mem = std.mem;

const util = @import("util.zig");
const frame = @import("frame.zig");
const tls = @import("tls.zig");
const q_crypto = @import("crypto.zig");

const VariableLengthInt = util.VariableLengthInt;

const HeaderForm = enum(u1) {
    short = 0b0,
    long = 0b1,
};

const LongHeaderPacketTypes = enum(u2) {
    initial = 0x00,
    zero_rtt = 0x01,
    handshake = 0x02,
    retry = 0x03,
};

const MAX_CID_LENGTH = 255;
const MIN_UDP_PAYLOAD_LENGTH = 1200;

pub const QUIC_VERSION_1 = 0x00000001;
pub const ConnectionId = std.BoundedArray(u8, MAX_CID_LENGTH);

pub const InitialPacket = struct {
    reserved_bits: u2 = 0x0,
    pn_length: u2,

    version: u32 = QUIC_VERSION_1,
    dst_cid: ConnectionId,
    src_cid: ConnectionId,
    token: std.ArrayList(u8),
    packet_number: u32,

    payload: std.ArrayList(frame.Frame),

    const Self = @This();

    pub fn deinit(self: Self) void {
        self.token.deinit();
        self.payload.deinit();
    }

    pub fn encodeEncrypted(
        self: *const Self,
        writer: anytype,
        allocator: mem.Allocator,
        tls_provider: tls.Provider,
    ) !void {
        // make plain text payload array
        // plain text is (packet number) + (frame payloads) + (padding)
        var plain_text = std.ArrayList(u8).init(allocator);
        defer plain_text.deinit();

        for (self.payload.items) |*frame_item| {
            try frame_item.encode(plain_text.writer());
        }

        // create padding field
        const len_without_length_field = blk: {
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

        // create header
        const token_length = try self.tokenLengthVli();
        const length_field = plain_text.items.len + self.decodePnLength() + aes_gcm.Aes128Gcm.tag_length;
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
        try token_length.encode(h_writer);
        try h_writer.writeAll(self.token.items);
        try rem_length.encode(h_writer);
        try h_writer.writeAll(pn_array[pn_array.len - self.decodePnLength() ..]);

        const client_initial = tls_provider.client_initial.?;

        // encrypt
        const encrypted_bytes = try q_crypto.encryptInitialPacket(
            aes_gcm.Aes128Gcm,
            header.items,
            plain_text.items,
            client_initial.key,
            client_initial.iv,
            client_initial.hp,
            allocator,
        );
        defer encrypted_bytes.deinit();

        // write to writer
        try writer.writeAll(encrypted_bytes.items);
        return;
    }

    /// get payload encoded length without padding field
    pub fn payloadByteLength(self: *const Self) usize {
        var len: usize = 0;
        for (self.payload.items) |*frame_item| {
            len += frame_item.getEncLen();
        }
        return len;
    }

    /// return first byte as u8
    pub fn firstByte(self: *const Self) u8 {
        var first_byte: u8 = 0;
        first_byte |= @intCast(u8, @enumToInt(HeaderForm.long)) << 7;
        first_byte |= 0b01000000;
        first_byte |= @intCast(
            u8,
            @enumToInt(LongHeaderPacketTypes.initial),
        ) << 4;
        first_byte |= @intCast(u8, self.reserved_bits) << 2;
        first_byte |= @intCast(u8, self.pn_length);
        return first_byte;
    }

    /// decode packet number length to usize
    pub fn decodePnLength(self: *const Self) usize {
        return @intCast(usize, self.pn_length) + 1;
    }

    /// return token length in VariableLengthInt struct
    pub fn tokenLengthVli(
        self: *const Self,
    ) VariableLengthInt.Error!VariableLengthInt {
        return VariableLengthInt.fromInt(self.token.items.len);
    }

    /// return (header without "length" field length) + (not padded payload length)
    pub fn headerLengthWithoutLengthField(self: *const Self) !usize {
        // zig fmt: off
        const len_without_length_field: usize = 
            ( 7    // first byte + version field + dcid len field + scid len field
            + self.dst_cid.len
            + self.src_cid.len
            + token_len: {
                const token_length = try self.tokenLengthVli();
                break :token_len token_length.len;
            }
            + self.token.items.len
            + self.decodePnLength());
        // zig fmt: on
        return len_without_length_field;
    }
};

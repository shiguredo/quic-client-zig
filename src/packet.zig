const std = @import("std");
const buffer = @import("./buffer.zig");
const util = @import("./util.zig");

const Buffer = buffer.Buffer;
const BufferError = buffer.BufferError;
const crypto = std.crypto;
const ArrayList = std.ArrayList;

const Frame = @import("./frame.zig").Frame;

const Header = struct {
    const Self = @This();
    const MAX_ID_LENGTH = 255;

    first_byte: u8,

    packet_number_length: u16,
    version: u32,

    destination_connection_id_length: u8,
    destination_connection_id: [MAX_ID_LENGTH]u8,

    source_connection_id_length: u8,
    source_connection_id: [MAX_ID_LENGTH]u8,

    token: ?ArrayList(u8),

    packet_number: [4]u8,

    const QUIC_VERSION_1: u32 = 0x00000001;

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

    const FIRST_BYTE_FIXED_BIT: comptime_int = 0b01000000;

    pub fn initialPacketHeader(given_source_id: ?[]u8, given_destination_id: ?[]u8) Self {
        const first_byte: u8 = 0x00;
        first_byte |= @enumToInt(HeaderForm.long) << 7;
        first_byte |= FIRST_BYTE_FIXED_BIT;
        first_byte |= @enumToInt(LongHeaderPacketTypes.initial) << 4;

        var source_id_length: u8 = undefined;
        var source_id: [MAX_ID_LENGTH]u8 = undefined;
        if (given_source_id) |s_id| { // if source connection id is given by server
            source_id_length = @intCast(u8, s_id.len);
            for (s_id) |value, index| {
                source_id[index] = value;
            }
        } else { // if source connection id is not given
            source_id_length = 8;
            for (source_id[0..source_id_length]) |_, index| {
                source_id[index] = crypto.random.int(u8);
            }
        }

        var destination_id_length: u8 = undefined;
        var destination_id: [MAX_ID_LENGTH]u8 = undefined;
        if (given_destination_id) |d_id| { // if destination connection id is given by server
            destination_id_length = @intCast(u8, d_id.len);
            for (d_id) |value, index| {
                destination_id[index] = value;
            }
        } else { // if source connection id is not given (first initial packet)
            destination_id_length = 8;
            for (destination_id[0..destination_id_length]) |_, index| {
                destination_id[index] = crypto.random.int(u8);
            }
        }

        // TODO: PacketNumber
        // TODO: Token

        return .{
            .first_byte = first_byte,
            .version = QUIC_VERSION_1,
            .destination_connection_id_length = destination_id_length,
            .destination_connection_id = destination_id,
            .source_connection_id_length = source_id_length,
            .source_connection_id = source_id,
            .token = null,
            .packet_number = 0,
        };
    }
};

const Packet = struct {
    const Self = @This();

    header: Header,
    frames: ArrayList(Frame),

    pub fn encode(self: *Self, buf: *Buffer) !void {
        var count: usize = 0;
        var slice = try buf.getOffsetSlice(0);
        const header = self.header;
        const frames = self.frames;

        slice[count] = header.first_byte;
        count += 1;

        const big_endian_version = util.getBigEndianInt(u32, header.version);
        const version_byte_count = @sizeOf(u32);
        @memcpy(@ptrCast([*]u8, big_endian_version), slice[count..(count + version_byte_count)], version_byte_count);
        count += version_byte_count;

        const destination_id_length = header.destination_connection_id_length;
        slice[count] = destination_id_length;
        count += 1;
        @memcpy(slice[count..(count + @intCast(usize, destination_id_length))], header.destination_connection_id[0..destination_id_length], destination_id_length);
        count += destination_id_length;

        const source_id_length = header.source_connection_id_length;
        slice[count] = source_id_length;
        count += 1;
        @memcpy(slice[count..(count + @intCast(usize, source_id_length))], header.source_connection_id[0..source_id_length], source_id_length);
        count += source_id_length;

        // TODO: switching by header type
        // TODO: writing frames
    }
};

// TODO: test for packet

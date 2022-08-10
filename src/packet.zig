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

    firstByte: u8,

    packetNumberLength: u16,
    version: u32,

    destinationConnectionIdLength: u8,
    destinationConnectionId: [MAX_ID_LENGTH]u8,

    sourceConnectionIdLength: u8,
    sourceConnectionId: [MAX_ID_LENGTH]u8,

    token: ?ArrayList(u8),

    packetNumber: [4]u8,

    const QUIC_VERSION_1: u32 = 0x00000001;

    const HeaderForm = enum(u1) {
        short = 0b0,
        long = 0b1,
    };

    const LongHeaderPacketTypes = enum(u2) {
        Initial = 0x00,
        ZeroRtt = 0x01,
        Handshake = 0x02,
        Retry = 0x03,
    };

    const FIRST_BYTE_FIXED_BIT: comptime_int = 0b01000000;

    pub fn initialPacketHeader(givenSourceId: ?[]u8, givenDestinaitonId: ?[]u8) Self {
        const firstByte: u8 = 0x00;
        firstByte |= @enumToInt(HeaderForm.long) << 7;
        firstByte |= FIRST_BYTE_FIXED_BIT;
        firstByte |= @enumToInt(LongHeaderPacketTypes.Initial) << 4;

        var sourceIdLength: u8 = undefined;
        var sourceId: [MAX_ID_LENGTH]u8 = undefined;
        if (givenSourceId) |sId| { // if source connection id is given by server
            sourceIdLength = @intCast(u8, sId.len);
            for (sId) |value, index| {
                sourceId[index] = value;
            }
        } else { // if source connection id is not given
            sourceIdLength = 8;
            for (sourceId[0..sourceIdLength]) |_, index| {
                sourceId[index] = crypto.random.int(u8);
            }
        }

        var destinationIdLength: u8 = undefined;
        var destinationId: [MAX_ID_LENGTH]u8 = undefined;
        if (givenDestinationId) |dId| { // if destination connection id is given by server
            destinationIdLength = @intCast(u8, dId.len);
            for (dId) |value, index| {
                destinationId[index] = value;
            }
        } else { // if source connection id is not given (first initial packet)
            destinationIdLength = 8;
            for (destinationId[0..destinaitonIdLength]) |_, index| {
                destinationId[index] = crypto.random.int(u8);
            }
        }

        // TODO: PacketNumber
        // TODO: Token

        return .{
            .firstByte = firstByte,
            .version = QUIC_VERSION_1,
            .destinaitonIdLength = destinationIdLength,
            .destinaitonId = destinationId,
            .sourceIdLength = sourceIdLength,
            .sourceId = sourceId,
            .token = null,
            .packetNumber = 0,
        };
    }
};

const Packet = struct {
    const Self = @This();

    header: Header,
    frames: ArrayList(Frame),

    pub fn writeBuffer(self: *Self, buffer: *Buffer) !void {
        var count: usize = 0;
        var slice = try buffer.getOffsetSlice(0);
        const header = self.header;
        const frames = self.frames;

        slice[count] = header.firstByte;
        count += 1;

        const bigEndianVersion = util.getBigEndianInt(u32, header.version);
        const versionByteCount = @sizeOf(u32);
        @memcpy(@ptrCast([*]u8, bigEndianVersion), slice[count..(count + versionByteCount)]);
        count += versionByteCount;

        const destinationIdLength = header.destinationConnectionIdLength;
        slice[count] = destinationIdLength;
        count += 1;
        @memcpy(slice[count..(count + @intCast(usize, destinationIdLength))], header.destinationConnectionId[0..destinationIdLength]);
        count += destinationIdLength;

        const sourceIdLength = header.sourceConnectionIdLength;
        slice[count] = sourceIdLength;
        count += 1;
        @memcpy(slice[count..(count + @intCast(usize, sourceIdLength))], header.sourceConnectionId[0..sourceIdLength]);
        count += sourceIdLength;

        // TODO: switching by header type
        // TODO: writing frames
    }
};

// TODO: test for packet

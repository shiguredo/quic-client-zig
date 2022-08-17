const std = @import("std");
const ArrayList = std.ArrayList;

const util = @import("util.zig");
const VariableLengthInt = util.VariableLengthInt;

const FrameType = enum {
    padding,
    ack,
    crypto,
    stream,
    handshake_done,
};

const Frame = union(FrameTypes) {
    padding: PaddingFrame,
    ack: AckFrame,
    crypto: CryptoFrame,
    stream: StreamFrame,
    handshake_done: HandshakeDoneFrame,
};

const PaddingFrame = struct {
    length: usize,
};

const AckFrame = struct {
    type_id: VariableLengthInt,
    largest_acknowledged: VariableLengthInt,
    ack_delay: VariableLengthInt,
    ack_range_count: VariableLengthInt,
    first_ack_range: VariableLengthInt,
    ack_ranges: ArrayList(AckRange),
    ecn_counts: EcnCounts,

    const AckRange = struct {
        gap: VariableLengthInt,
        ack_range_length: VariableLengthInt,
    };

    const EcnCounts = struct {
        ect0: VariableLengthInt,
        ect1: VariableLengthInt,
        ecn_cn: VariableLengthInt,
    };
};

const CryptoFrame = struct {
    offset: VariableLengthInt,
    length: VariableLengthInt,
    data: []u8,
};

const StreamFrame = struct {
    type_id: VariableLengthInt,
    stream_id: VariableLengthInt,
    offset: VariableLengthInt,
    length: VariableLengthInt,
    data: []u8,
};

const HandshakeDoneFrame = struct {};

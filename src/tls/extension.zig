const std = @import("std");
const mem = std.mem;
const testing = std.testing;

const HandshakeType = @import("handshake.zig").HandshakeType;

pub const ExtensionType = enum(u16) {
    supported_groups = 10,
    signature_algorithms = 13,
    supported_versions = 43,
    key_share = 51,
    quic_transport_parameters = 0x39,
};

/// TLS message extensions.
/// see https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2
pub const Extension = union(ExtensionType) {
    supported_groups: SupportedGroups,
    signature_algorithms: SignatureAlgorithms,
    supported_versions: SupportedVersions,
    key_share: KeyShare,
    quic_transport_parameters: QuicTransportParameters,

    const Self = @This();

    const Error = error{
        InvalidExtensionFormat,
    };

    pub fn deinit(self: Self) void {
        switch (self) {
            .key_share => |e| e.deinit(),
            .quic_transport_parameters => |e| e.deinit(),
            else => {},
        }
    }

    /// get encoded byte size
    pub fn getEncLen(self: *const Self) usize {
        var len: usize = 0;
        len += @sizeOf(ExtensionType);
        len += @sizeOf(u16); // content length field
        len += switch (self.*) {
            .supported_groups => |e| e.getEncLen(),
            .signature_algorithms => |e| e.getEncLen(),
            .supported_versions => |e| e.getEncLen(),
            .key_share => |e| e.getEncLen(),
            .quic_transport_parameters => |e| e.getEncLen(),
        };
        return len;
    }

    /// encode self to writer
    pub fn encode(self: *const Self, writer: anytype) !void {
        const ext_type = @as(ExtensionType, self.*);
        try writer.writeIntBig(u16, @enumToInt(ext_type));

        const data_len = switch (self.*) {
            .supported_groups => |e| e.getEncLen(),
            .signature_algorithms => |e| e.getEncLen(),
            .supported_versions => |e| e.getEncLen(),
            .key_share => |e| e.getEncLen(),
            .quic_transport_parameters => |e| e.getEncLen(),
        };
        try writer.writeIntBig(u16, @intCast(u16, data_len));

        switch (self.*) {
            .supported_groups => |e| try e.encode(writer),
            .signature_algorithms => |e| try e.encode(writer),
            .supported_versions => |e| try e.encode(writer),
            .key_share => |e| try e.encode(writer),
            .quic_transport_parameters => |e| try e.encode(writer),
        }
    }

    pub fn decode(msg_type: HandshakeType, reader: anytype, allocator: mem.Allocator) !Self {
        const type_value = try reader.readIntBig(u16);
        const type_enum = switch (type_value) {
            10, 13, 43, 51, 0x39 => @intToEnum(ExtensionType, type_value),
            else => return Error.InvalidExtensionFormat,
        };

        const ext_data_len = try reader.readIntBig(u16);
        var ext_stream = std.io.limitedReader(reader, @intCast(u64, ext_data_len));
        var ext_reader = ext_stream.reader();

        return switch (type_enum) {
            .supported_versions => Self{
                .supported_versions = try SupportedVersions.decode(msg_type, ext_reader),
            },
            .key_share => Self{
                .key_share = try KeyShare.decode(msg_type, ext_reader, allocator),
            },
            else => unreachable, // TODO: implement decode() for other extensions
        };
    }
};

pub const SupportedGroups = @import("extension/supported_groups.zig").SupportedGroups;
pub const SignatureAlgorithms = @import("extension/signature_algorithms.zig").SignatureAlgorithms;
pub const SupportedVersions = @import("extension/supported_versions.zig").SupportedVersions;
pub const KeyShare = @import("extension/key_share.zig").KeyShare;
pub const QuicTransportParameters = @import("extension/quic_transport_parameters.zig").QuicTransportParameters;

pub const NamedGroup = enum(u16) {
    // Elliptic Curve Groups (ECDHE)
    secp256r1 = 0x0017,
    secp384r1 = 0x0018,
    secp521r1 = 0x0019,
    x25519 = 0x001D,
    x448 = 0x001E,

    // Finite Field Groups (DHE)
    ffdhe2048 = 0x0100,
    ffdhe3072 = 0x0101,
    ffdhe4096 = 0x0102,
    ffdhe6144 = 0x0103,
    ffdhe8192 = 0x0104,

    // Reserved Code Points
    ffdhe_private_use,
    ecdhe_private_use,

    const Self = @This();

    pub fn cast(value: u16) error{EnumCastFailed}!Self {
        return switch (value) {
            0x0017...0x0019,
            0x001D...0x001E,
            0x0100...0x0104,
            => @intToEnum(Self, value),
            else => return error.EnumCastFailed,
        };
    }
};

pub const SignatureScheme = enum(u16) {
    // RSASSA-PKCS1-v1_5 algorithms
    rsa_pksc1_sha256 = 0x0401,
    rsa_pksc1_sha384 = 0x0501,
    rsa_pksc1_sha512 = 0x0601,

    // ECDSA algorithms
    ecdsa_secp256r1_sha256 = 0x0403,
    ecdsa_secp384r1_sha384 = 0x0503,
    ecdsa_secp512r1_sha512 = 0x0603,

    // RSASSA-PSS algorithms with public key OID rsaEncryption
    rsa_pss_rsae_sha256 = 0x0804,
    rsa_pss_rsae_sha384 = 0x0805,
    rsa_pss_rsae_sha512 = 0x0806,

    // EdDSA algorithms
    ed25519 = 0x0807,
    ed448 = 0x0808,

    // RSASSA-PSS algorithms with public key OID RSASSA-PSS
    rsa_pss_pss_sha256 = 0x0809,
    rsa_pss_pss_sha384 = 0x080a,
    rsa_pss_pss_sha512 = 0x080b,

    // Legacy algorithms
    rsa_pkcs1_sha1 = 0x0201,
    ecdsa_sha1 = 0x0203,

    // Reserved Code Points
    private_use,
};

test "Extension" {
    const Buffer = @import("../util.zig").Buffer;
    var buf = Buffer(1024).init();

    // supported groups
    var sg_ext = sg_ext: {
        var sg = SupportedGroups.init();
        try sg.append(.x25519);
        break :sg_ext Extension{ .supported_groups = sg };
    };
    defer sg_ext.deinit();
    try sg_ext.encode(buf.writer());
    try testing.expectFmt(
        "000A00040002001D",
        "{s}",
        .{std.fmt.fmtSliceHexUpper(buf.getUnreadSlice())},
    );
    try testing.expectEqual(buf.unreadLength(), sg_ext.getEncLen());

    // signature algorithms
    buf.clear();
    var sa_ext = sa_ext: {
        var sa = SignatureAlgorithms.init();
        try sa.appendSlice(&[_]SignatureScheme{
            .ecdsa_secp256r1_sha256,
            .rsa_pss_rsae_sha256,
            .rsa_pksc1_sha256,
        });
        break :sa_ext Extension{ .signature_algorithms = sa };
    };
    defer sa_ext.deinit();
    try sa_ext.encode(buf.writer());
    try testing.expectFmt(
        "000D00080006040308040401",
        "{s}",
        .{std.fmt.fmtSliceHexUpper(buf.getUnreadSlice())},
    );
    try testing.expectEqual(buf.unreadLength(), sa_ext.getEncLen());

    // supported versions
    buf.clear();
    var sv_ext = sv_ext: {
        var sv = SupportedVersions.init(.client_hello);
        try sv.append(SupportedVersions.TLS13);
        break :sv_ext Extension{ .supported_versions = sv };
    };
    defer sv_ext.deinit();
    try sv_ext.encode(buf.writer());
    try testing.expectFmt(
        "002B0003020304",
        "{s}",
        .{std.fmt.fmtSliceHexUpper(buf.getUnreadSlice())},
    );
    try testing.expectEqual(buf.unreadLength(), sv_ext.getEncLen());

    // key share
    buf.clear();
    var ks_ext = ks_ext: {
        var ks = KeyShare.init(.client_hello, testing.allocator);
        break :ks_ext Extension{ .key_share = ks };
    };
    defer ks_ext.deinit();
    try ks_ext.encode(buf.writer());
    try testing.expectFmt(
        "003300020000",
        "{s}",
        .{std.fmt.fmtSliceHexUpper(buf.getUnreadSlice())},
    );
    try testing.expectEqual(buf.unreadLength(), ks_ext.getEncLen());
}

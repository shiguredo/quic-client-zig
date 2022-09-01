const std = @import("std");
const mem = std.mem;
const crypto = std.crypto;
const extension = @import("extension.zig");
const Extension = extension.Extension;

const LEGACY_VERSION: u16 = 0x0303;
const RANDOM_FIELD_LEN = 32;
const SessionId = std.BoundedArray(u8, 32);
const Extensions = std.ArrayList(Extension);

pub const ClientHello = struct {
    const CipherSuites = std.BoundedArray([2]u8, 65536 / @sizeOf([2]u8));
    const CompressionMethods = std.BoundedArray(u8, 256);

    random_bytes: [32]u8,
    legacy_session_id: SessionId,
    cipher_suites: CipherSuites,
    legacy_compression_methods: CompressionMethods,
    extensions: Extensions,

    const Self = @This();

    pub fn init(allocator: mem.Allocator) !Self {
        var instance = Self{
            .random_bytes = undefined,
            .legacy_session_id = try SessionId.init(0),
            .cipher_suites = try CipherSuites.init(0),
            .legacy_compression_methods = try CompressionMethods.init(0),
            .extensions = Extensions.init(allocator),
        };

        crypto.random.bytes(&instance.random_bytes); // assign random bytes
        try instance.legacy_compression_methods.appendSlice(&[_]u8{0}); // value for "null"

        return instance;
    }

    pub fn deinit(self: Self) void {
        for (self.extensions.items) |*ext| {
            ext.deinit();
        }
        self.extensions.deinit();
    }

    pub fn appendCipher(self: *Self, cipher_suite: [2]u8) error{Overflow}!void {
        try self.cipher_suites.append(cipher_suite);
    }

    pub fn appendExtension(self: *Self, ext: Extension) mem.Allocator.Error!void {
        try self.extensions.append(ext);
    }

    pub fn appendExtensionSlice(
        self: *Self,
        exts: []const Extension,
    ) mem.Allocator.Error!void {
        try self.extensions.appendSlice(exts);
    }

    /// get encoded bytes size
    pub fn getEncLen(self: *const Self) usize {
        var len: usize = blk: {
            comptime var temp = 0;
            temp += @sizeOf(u16); // legacy version field
            temp += RANDOM_FIELD_LEN;
            break :blk temp;
        };

        len += @sizeOf(u8); // session id's length field
        len += @sizeOf(u8) * self.legacy_session_id.len;

        len += @sizeOf(u16); // cipher suites' length field
        len += @sizeOf([2]u8) * self.cipher_suites.len;

        len += @sizeOf(u8); // commpression methods' length field
        len += @sizeOf(u8) * self.legacy_compression_methods.len;

        len += @sizeOf(u16); // extension length field
        for (self.extensions.items) |*ext| {
            len += ext.getEncLen();
        }

        return len;
    }

    /// encode self to writer
    pub fn encode(self: *const Self, writer: anytype) !void {
        // legacy_version
        try writer.writeIntBig(u16, LEGACY_VERSION);

        // ramdom
        _ = try writer.write(&self.random_bytes);

        // legacy_session_id
        try writer.writeIntBig(u8, @intCast(u8, self.legacy_session_id.len));
        _ = try writer.write(self.legacy_session_id.constSlice());

        // cipher_suites
        const suites_byte_ptr = mem.sliceAsBytes(self.cipher_suites.constSlice());
        try writer.writeIntBig(u16, @intCast(u16, suites_byte_ptr.len));
        _ = try writer.write(suites_byte_ptr);

        // legacy_compression_methods
        try writer.writeIntBig(u8, @intCast(u8, self.legacy_compression_methods.len));
        _ = try writer.write(self.legacy_compression_methods.constSlice());

        // extensions
        var ext_total_len: usize = 0;
        for (self.extensions.items) |*ext| ext_total_len += ext.getEncLen();
        try writer.writeIntBig(u16, @intCast(u16, ext_total_len));

        for (self.extensions.items) |*ext| try ext.encode(writer);

        return;
    }
};

pub const ServerHello = struct {
    random_bytes: [RANDOM_FIELD_LEN]u8,
    legacy_session_id_echo: SessionId,
    cipher_suite: [2]u8,
    extensions: Extensions,

    const Self = @This();

    const Error = error{
        InvalidServerHelloFormat,
    };

    pub fn deinit(self: Self) void {
        for (self.extensions.items) |ext| {
            ext.deinit();
        }
        self.extensions.deinit();
    }

    pub fn decode(reader: anytype, allocator: mem.Allocator) !Self {
        var instance: Self = undefined;

        // read legacy version
        const legacy_version = try reader.readIntBig(u16);
        std.log.debug("{d}\n", .{legacy_version});
        if (legacy_version != @as(u16, 0x0303)) return Error.InvalidServerHelloFormat;

        // read random bytes
        try reader.readNoEof(&instance.random_bytes);

        // read session id
        const session_id_len = try reader.readIntBig(u8);
        instance.legacy_session_id_echo = try SessionId.init(@intCast(usize, session_id_len));
        try reader.readNoEof(instance.legacy_session_id_echo.slice());

        // read cipher suites
        try reader.readNoEof(&instance.cipher_suite);

        const legacy_commpression_method_len = try reader.readIntBig(u8);
        if (legacy_commpression_method_len != @as(u8, 0)) return Error.InvalidServerHelloFormat;

        const ext_len = try reader.readIntBig(u16);
        var ext_list = std.ArrayList(Extension).init(allocator);

        var ext_stream = std.io.limitedReader(reader, @intCast(u64, ext_len));
        var ext_reader = ext_stream.reader();
        while (Extension.decode(.server_hello, ext_reader, allocator)) |ext| {
            try ext_list.append(ext);
        } else |err| switch (err) {
            error.EndOfStream => {}, // ok
            else => return err,
        }

        instance.extensions = ext_list;

        return instance;
    }
};

const std = @import("std");
const mem = std.mem;
const crypto = std.crypto;
const testing = std.testing;
const fmt = std.fmt;
const io = std.io;

const connection = @import("../connection.zig");
const q_crypto = @import("../crypto.zig");
const HkdfAbst = q_crypto.HkdfAbst;
const AeadAbst = q_crypto.AeadAbst;
const tls = @import("../tls.zig");
const HandshakeRaw = @import("handshake.zig").HandshakeRaw;
const extension = tls.extension;
const Buffer = @import("../buffer.zig").Buffer;

const QuicApi = @import("quic_api.zig").QuicApi;

const Sha256 = q_crypto.Sha256;
const Hmac = q_crypto.Hmac;
const Hkdf = q_crypto.Hkdf;
const X25519 = crypto.dh.X25519;

///  TLS client's state machine
///  https://www.rfc-editor.org/rfc/rfc8446#appendix-A.1
pub const State = enum {
    start,
    wait_sh,
    wait_ee,
    wait_cert_cr,
    wait_cert,
    wait_cv,
    wait_fin,
    connected,
};

pub const Epoch = enum {
    initial,
    zero_rtt,
    handshake,
    one_rtt,
    no_crypto,
};

pub const TlsKey = struct {
    secret: [Hmac.key_length]u8 = undefined,

    const Self = @This();

    /// derive handshake traffic keys for client
    pub fn deriveHandshakeClient(tls_secret: [Hmac.key_length]u8, message: []const u8) Self {
        var instance: Self = undefined;
        deriveSecret(HkdfAbst.get(.sha256), &instance.secret, tls_secret, "c hs traffic", message);
        return instance;
    }

    /// derive handshake traffic keys for server
    pub fn deriveHandshakeServer(tls_secret: [Hmac.key_length]u8, message: []const u8) Self {
        var instance: Self = undefined;
        deriveSecret(HkdfAbst.get(.sha256), &instance.secret, tls_secret, "s hs traffic", message);
        return instance;
    }

    /// derive handshake traffic keys for client
    pub fn deriveApplicationClient(tls_secret: [Hmac.key_length]u8, message: []const u8) Self {
        var instance: Self = undefined;
        deriveSecret(HkdfAbst.get(.sha256), &instance.secret, tls_secret, "c ap traffic", message);
        return instance;
    }

    /// derive handshake traffic keys for server
    pub fn deriveApplicationServer(tls_secret: [Hmac.key_length]u8, message: []const u8) Self {
        var instance: Self = undefined;
        deriveSecret(HkdfAbst.get(.sha256), &instance.secret, tls_secret, "s ap traffic", message);
        return instance;
    }
};

/// TODO: implement this function in HkdfAbst and remove this.
pub fn deriveSecret(
    hkdf: HkdfAbst,
    out: *[Hmac.key_length]u8,
    secret: [Hmac.key_length]u8,
    label: []const u8,
    message: []const u8,
) void {
    var h: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(message, &h, .{}); // TODO: replace Sha256

    hkdf.expandLabel(out, &secret, label, &h);
}

/// note: only supports aes128gcm for AEAD and hkdfsha256 for HKDF now
/// `ApiType` in the argument must be quic_api.QuicApi()'s return type
pub fn ClientImpl(comptime ApiType: type) type {
    return struct {
        api: ApiType,

        state: State = .start,

        initial_secret: [Hmac.key_length]u8 = undefined,
        client_initial: ?TlsKey = null,
        server_initial: ?TlsKey = null,

        early_secret: ?[Hmac.key_length]u8 = null,
        handshake_secret: ?[Hmac.key_length]u8 = null,
        client_handshake: ?TlsKey = null,
        server_handshake: ?TlsKey = null,
        master_secret: ?[Hmac.key_length]u8 = null,
        client_master: ?TlsKey = null,
        server_master: ?TlsKey = null,

        x25519_keypair: ?X25519.KeyPair = null,
        x25519_peer: ?[X25519.public_length]u8 = null,

        shared_key: ?[X25519.shared_length]u8 = null,

        /// client hello raw data
        raw_ch: ?HandshakeRaw = null,
        /// server hello raw data
        raw_sh: ?HandshakeRaw = null,
        /// encrypted extensions raw data
        raw_ee: ?HandshakeRaw = null,
        /// certificate raw data
        raw_cert: ?HandshakeRaw = null,
        /// certificate verify raw data
        raw_cv: ?HandshakeRaw = null,
        /// server finished raw data
        raw_sfin: ?HandshakeRaw = null,

        allocator: mem.Allocator,

        const Self = @This();

        pub const QuicApi = ApiType;

        pub const Error = error{ KeyNotInstalled, MessageNotInstalled };
        const HandshakeHandlingError =
            error{ MessageIncomplete, HandshakeTypeError };

        const BUF_SIZE = 2048;

        pub fn init(allocator: mem.Allocator) Self {
            var instance = Self{
                .api = undefined,
                .allocator = allocator,
            };
            return instance;
        }

        pub fn initWithApi(allocator: mem.Allocator, api: ApiType) Self {
            var instance = Self.init(allocator);
            instance.api = api;
            return instance;
        }

        pub fn deinit(self: *Self) void {
            if (self.raw_ch) |h| h.deinit();
            if (self.raw_sh) |h| h.deinit();
            if (self.raw_ee) |h| h.deinit();
            if (self.raw_cert) |h| h.deinit();
            if (self.raw_cv) |h| h.deinit();
            if (self.raw_sfin) |h| h.deinit();
        }

        /// initiate TLS handshake, takes QUIC source connection ID and initial crypto stream.
        pub fn initiateHandshake(
            self: *Self,
            c_scid: connection.ConnectionId,
        ) !void {
            try self.setUpMyX25519KeyPair();
            var writer = self.api.getWriter(.initial);
            var ch_msg = try self.createClientHello(c_scid.id.constSlice());
            defer ch_msg.deinit();
            var buf = [_]u8{0} ** 1024;
            var stream = io.fixedBufferStream(&buf);
            try ch_msg.encode(stream.writer());
            try writer.writeAll(stream.getWritten());
        }

        /// Read data from
        pub fn doHandshake(
            self: *Self,
            data: []const u8,
        ) !void {
            if (self.state == .start) {
                return;
            }

            var buf = Buffer(BUF_SIZE).init();
            var stream = io.fixedBufferStream(data);
            var reader = stream.reader();

            read_loop: while (true) {
                try buf.readFrom(reader);
                if (buf.unreadLength() == 0) break;

                // write data to current state's handshakeRaw struct
                var raw_hs_ptr = switch (self.state) {
                    .wait_sh => &self.raw_sh,
                    .wait_ee => &self.raw_ee,
                    .wait_cert_cr => &self.raw_cert,
                    .wait_cv => &self.raw_cv,
                    .wait_fin => &self.raw_sfin,
                    else => unreachable,
                };
                handleRaw(raw_hs_ptr, &buf, self.allocator) catch |err| {
                    if (err == error.DataTooShort) {
                        buf.realign();
                        continue :read_loop;
                    } else return err;
                };

                // call current state's handling function
                switch (self.state) {
                    .wait_sh => try self.handleServerHello(),
                    .wait_ee => try self.handleEncryptedExtensions(),
                    .wait_cert_cr => try self.handleCertificate(),
                    .wait_cv => try self.handleCertificateVerify(),
                    .wait_fin => {
                        var writer = self.api.getWriter(.handshake);
                        try self.handleFinished();
                        try self.writeFinished(writer);
                    },
                    else => unreachable,
                }
            }
        }

        // private functions

        fn setUpMyX25519KeyPair(self: *Self) !void {
            self.x25519_keypair = try crypto.dh.X25519.KeyPair.create(null);
        }

        fn deriveSharedKey(self: *Self) !void {
            self.shared_key = if (self.x25519_keypair != null and self.x25519_peer != null) ecdhe: {
                break :ecdhe try X25519.scalarmult(self.x25519_keypair.?.secret_key, self.x25519_peer.?);
            } else return Error.KeyNotInstalled;
        }

        /// setup early key
        fn setUpEarly(self: *Self, psk: ?[]const u8) void {
            const ikm = psk orelse &[_]u8{0} ** Hmac.key_length;
            self.early_secret = Hkdf.extract(&[_]u8{0}, ikm);
        }

        /// setup handshake key
        fn setUpHandshake(self: *Self) !void {
            const allocator = self.allocator;
            const early_secret = self.early_secret orelse return Error.KeyNotInstalled;
            var early_derived: [Sha256.digest_length]u8 = undefined;
            deriveSecret(HkdfAbst.get(.sha256), &early_derived, early_secret, "derived", "");

            const ecdhe_input = self.shared_key orelse [_]u8{0} ** Hmac.key_length;
            const hs_secret = Hkdf.extract(&early_derived, &ecdhe_input);
            self.handshake_secret = hs_secret;

            if (self.raw_ch) |raw_ch| if (self.raw_sh) |raw_sh| {
                const message = try mem.concat(allocator, u8, &[_][]const u8{
                    raw_ch.data.items,
                    raw_sh.data.items,
                });
                defer allocator.free(message);
                const client_handshake = TlsKey.deriveHandshakeClient(hs_secret, message);
                const server_handshake = TlsKey.deriveHandshakeServer(hs_secret, message);
                self.client_handshake = client_handshake;
                self.server_handshake = server_handshake;

                // TODO: make algorithm changable
                const hkdf = HkdfAbst.get(.sha256);
                const aead = AeadAbst.get(.aes128gcm);
                self.api.setWriteSecret(.handshake, aead, hkdf, &client_handshake.secret);
                self.api.setReadSecret(.handshake, aead, hkdf, &server_handshake.secret);
            } else return Error.MessageNotInstalled;
        }

        fn setUpMaster(self: *Self) !void {
            const allocator = self.allocator;
            const hs_secret = self.handshake_secret orelse return Error.KeyNotInstalled;
            var hs_derived: [Sha256.digest_length]u8 = undefined;
            deriveSecret(HkdfAbst.get(.sha256), &hs_derived, hs_secret, "derived", "");

            const extract_input = [_]u8{0} ** Hmac.key_length;
            const master_secret = Hkdf.extract(&hs_derived, &extract_input);
            self.master_secret = master_secret;

            const raw_ch = self.raw_ch orelse return Error.KeyNotInstalled;
            const raw_sh = self.raw_sh orelse return Error.KeyNotInstalled;
            const raw_ee = self.raw_ee orelse return Error.KeyNotInstalled;
            const raw_cert = self.raw_cert orelse return Error.KeyNotInstalled;
            const raw_cv = self.raw_cv orelse return Error.KeyNotInstalled;
            const raw_sfin = self.raw_sfin orelse return Error.KeyNotInstalled;

            const message = try mem.concat(allocator, u8, &[_][]const u8{
                raw_ch.data.items,
                raw_sh.data.items,
                raw_ee.data.items,
                raw_cert.data.items,
                raw_cv.data.items,
                raw_sfin.data.items,
            });
            defer allocator.free(message);
            const client_master = TlsKey.deriveApplicationClient(master_secret, message);
            const server_master = TlsKey.deriveApplicationServer(master_secret, message);

            self.client_master = client_master;
            self.server_master = server_master;

            // TODO: make algorithm changable
            const hkdf = HkdfAbst.get(.sha256);
            const aead = AeadAbst.get(.aes128gcm);
            self.api.setWriteSecret(.handshake, aead, hkdf, &client_master.secret);
            self.api.setReadSecret(.handshake, aead, hkdf, &server_master.secret);
        }

        /// Reads bytes from self.raw_sh and handle it
        /// when self.raw_sh is not completed (its length is shorter
        /// than the length field indicates), does nothing
        fn handleServerHello(
            self: *Self,
        ) !void {
            const raw_bytes =
                self.raw_sh orelse return;
            if (!raw_bytes.isComplete())
                return;

            var stream = std.io.fixedBufferStream(raw_bytes.data.items);
            const s_hello = try tls.Handshake.decode(stream.reader(), self.allocator);
            defer s_hello.deinit();

            for (s_hello.server_hello.extensions.items) |ext| {
                if (@as(extension.ExtensionType, ext) == .key_share) {
                    self.x25519_peer = [_]u8{0} ** 32;
                    mem.copy(u8, &self.x25519_peer.?, ext.key_share.server_share.?.key_exchange.items);
                }
            }

            // setup key
            self.setUpEarly(null);
            try self.deriveSharedKey();
            try self.setUpHandshake();

            // The next state is wait encrypted extensions
            self.state = .wait_ee;
        }

        /// TODO: implement handling encrypted extensions
        fn handleEncryptedExtensions(
            self: *Self,
        ) !void {
            const raw_bytes =
                self.raw_ee orelse return;
            if (!raw_bytes.isComplete())
                return;

            self.state = .wait_cert_cr;
        }

        /// TODO: implement handling certificate
        fn handleCertificate(
            self: *Self,
        ) !void {
            const raw_bytes =
                self.raw_cert orelse return;
            if (!raw_bytes.isComplete())
                return;

            self.state = .wait_cv;
        }

        /// TODO: implement handling certificate verify
        fn handleCertificateVerify(
            self: *Self,
        ) !void {
            const raw_bytes =
                self.raw_cv orelse return;
            if (!raw_bytes.isComplete())
                return;

            self.state = .wait_fin;
        }

        fn handleFinished(
            self: *Self,
        ) !void {
            const raw_bytes =
                self.raw_sfin orelse return;
            if (!raw_bytes.isComplete())
                return;

            // setup master keys
            try self.setUpMaster();

            self.state = .connected;
        }

        /// returns ClientHello contained in Handshake union
        fn createClientHello(
            self: *Self,
            quic_scid: []const u8,
        ) !tls.Handshake {
            const allocator = self.allocator;
            var c_hello = try tls.ClientHello.init(allocator);
            errdefer c_hello.deinit();
            try c_hello.appendCipher(.{ 0x13, 0x01 }); // TLS_AES_128_GCM_SHA256

            const my_kp = self.x25519_keypair orelse return Error.KeyNotInstalled;

            var extensions = [_]extension.Extension{
                supported_groups: {
                    var sg = extension.SupportedGroups.init();
                    try sg.append(.x25519);
                    break :supported_groups extension.Extension{ .supported_groups = sg };
                },
                signature_algorithms: {
                    var sa = extension.SignatureAlgorithms.init();
                    try sa.appendSlice(&[_]extension.SignatureScheme{
                        .ecdsa_secp256r1_sha256,
                        .rsa_pss_rsae_sha256,
                        .rsa_pksc1_sha256,
                    });
                    break :signature_algorithms extension.Extension{ .signature_algorithms = sa };
                },
                supported_versions: {
                    var sv = extension.SupportedVersions.init(.client_hello);
                    try sv.append(extension.SupportedVersions.TLS13);
                    break :supported_versions extension.Extension{ .supported_versions = sv };
                },
                key_share: {
                    var ks = extension.KeyShare.init(.client_hello, allocator);
                    var x25519_pub = std.ArrayList(u8).init(allocator);
                    try x25519_pub.appendSlice(&my_kp.public_key);
                    try ks.append(.{ .group = .x25519, .key_exchange = x25519_pub });
                    break :key_share extension.Extension{ .key_share = ks };
                },
                transport_param: {
                    var params = extension.QuicTransportParameters.init(allocator);
                    try params.appendParam(.initial_scid, quic_scid);
                    break :transport_param extension.Extension{ .quic_transport_parameters = params };
                },
            };

            try c_hello.appendExtensionSlice(&extensions);

            var hs = tls.Handshake{ .client_hello = c_hello };

            self.raw_ch = blk: {
                var temp = std.ArrayList(u8).init(allocator);
                try hs.encode(temp.writer());
                break :blk HandshakeRaw.fromArrayList(temp);
            };

            defer self.state = .wait_sh;
            return hs;
        }

        fn writeFinished(self: *Self, writer: anytype) !void {
            const raw_ch = self.raw_ch orelse return Error.MessageNotInstalled;
            const raw_sh = self.raw_sh orelse return Error.MessageNotInstalled;
            const raw_ee = self.raw_ee orelse return Error.MessageNotInstalled;
            const raw_cert = self.raw_cert orelse return Error.MessageNotInstalled;
            const raw_cv = self.raw_cv orelse return Error.MessageNotInstalled;
            const raw_sfin = self.raw_sfin orelse return Error.MessageNotInstalled;

            const messages = try mem.concat(
                self.allocator,
                u8,
                &[_][]const u8{
                    raw_ch.data.items,
                    raw_sh.data.items,
                    raw_ee.data.items,
                    raw_cert.data.items,
                    raw_cv.data.items,
                    raw_sfin.data.items,
                },
            );
            defer self.allocator.free(messages);

            const base_key =
                (self.client_handshake orelse return Error.KeyNotInstalled).secret;
            const finished_key = fkey: {
                var temp: [Sha256.digest_length]u8 = undefined;
                q_crypto.hkdfExpandLabel(&temp, base_key, "finished", "");
                break :fkey temp;
            };

            var buf: [4 + Hmac.mac_length]u8 = undefined; // message header length + verify data length
            buf[0..4].* = .{ 0x14, 0x00, 0x00, 0x20 };
            const hash = h: {
                var temp: [Sha256.digest_length]u8 = undefined;
                Sha256.hash(messages, &temp, .{});
                break :h temp;
            };
            Hmac.create(buf[4..], &hash, &finished_key);

            try writer.writeAll(&buf);
        }

        /// if raw_ptr.* is null create instance and write data to it
        /// else, write data to existing instance.
        fn handleRaw(
            raw_ptr: *?HandshakeRaw,
            buf_ptr: *Buffer(BUF_SIZE),
            allocator: mem.Allocator,
        ) !void {
            if (raw_ptr.*) |*raw| {
                const n = try raw.write(buf_ptr.getUnreadSlice());
                buf_ptr.discard(n);
                buf_ptr.realign();
            } else {
                raw_ptr.* = blk: {
                    if (buf_ptr.unreadLength() < 4) {
                        return error.DataTooShort;
                    }
                    const slice =
                        buf_ptr.getUnreadSlice();
                    const max_len =
                        mem.readIntBig(u24, slice[1..4]) + 4;
                    var raw = try HandshakeRaw.init(
                        allocator,
                        @intCast(usize, max_len),
                    );
                    const n = try raw.write(slice[0..std.math.min(max_len, slice.len)]);
                    buf_ptr.discard(n);
                    buf_ptr.realign();
                    break :blk raw;
                };
            }
        }
    };
}

fn allocParseHex(in: []const u8) ![]u8 {
    const buf = try testing.allocator.alloc(u8, in.len / 2);
    return try fmt.hexToBytes(buf, in);
}

/// dummy implementation for QUIC API
const DummyStream = struct {
    stream: Stream,

    pub const Error = Stream.WriteError;
    pub const Stream = io.FixedBufferStream([]u8);
    const Self = @This();

    pub const Api = QuicApi(Stream.WriteError);

    pub fn init(buf: []u8) Self {
        var instance = Self{
            .stream = io.fixedBufferStream(buf),
        };
        return instance;
    }

    pub fn setSecretDummy(_: *Self, _: Epoch, _: AeadAbst, _: HkdfAbst, _: []const u8) void {}

    pub fn writeData(self: *Self, _: Epoch, data: []const u8) Error!usize {
        // const info = @typeInfo(*Self);
        // const alignment = info.Pointer.alignment;
        // var self = @ptrCast(*Self, @alignCast(alignment, ptr));
        return self.stream.writer().write(data);
    }

    pub fn getApi(self: *Self) Api {
        return Api.init(
            self,
            setSecretDummy,
            setSecretDummy,
            writeData,
        );
    }
};

// simple 1-RTT Handshake from https://www.rfc-editor.org/rfc/rfc8448.html#section-3
test "handleStream" {
    const Provider = ClientImpl(DummyStream.Api);
    const allocator = testing.allocator;
    var dummy_buf = [_]u8{0} ** 4096;
    var dummy_stream = DummyStream.init(&dummy_buf);
    var dummy_api = dummy_stream.getApi();
    var client = Provider.initWithApi(allocator, dummy_api);
    defer client.deinit();

    // 1. setup client hello

    // 1-1. set client hello to client
    const raw_ch_hex =
        "010000c00303cb34ecb1e78163ba1c38c6dacb196a" ++
        "6dffa21a8d9912ec18a2ef6283024dece700000613" ++
        "0113031302010000910000000b0009000006736572" ++
        "766572ff01000100000a00140012001d0017001800" ++
        "190100010101020103010400230000003300260024" ++
        "001d002099381de560e4bd43d23d8e435a7dbafeb3" ++
        "c06e51c13cae4d5413691e529aaf2c002b00030203" ++
        "04000d0020001e0403050306030203080408050806" ++
        "04010501060102010402050206020202002d000201" ++
        "01001c00024001";
    client.raw_ch = HandshakeRaw.fromArrayList(
        std.ArrayList(u8).fromOwnedSlice(
            allocator,
            try allocParseHex(raw_ch_hex),
        ),
    );

    // 1-2. set key share to client
    client.x25519_keypair = .{
        .public_key = "\x99\x38\x1d\xe5\x60\xe4\xbd\x43\xd2\x3d\x8e\x43\x5a\x7d\xba\xfe\xb3\xc0\x6e\x51\xc1\x3c\xae\x4d\x54\x13\x69\x1e\x52\x9a\xaf\x2c".*,
        .secret_key = "\x49\xaf\x42\xba\x7f\x79\x94\x85\x2d\x71\x3e\xf2\x78\x4b\xcb\xca\xa7\x91\x1d\xe2\x6a\xdc\x56\x42\xcb\x63\x45\x40\xe7\xea\x50\x05".*,
    };

    // 1-3. set client.state .wait_sh
    client.state = .wait_sh;

    // 1-4. test
    try testing.expectFmt(
        raw_ch_hex,
        "{s}",
        .{fmt.fmtSliceHexLower(client.raw_ch.?.data.items)},
    );

    // 2. recieve server hello
    const raw_sh_hex =
        "020000560303a6af06a4121860dc5e6e60249cd34c" ++
        "95930c8ac5cb1434dac155772ed3e2692800130100" ++
        "002e00330024001d0020c9828876112095fe66762b" ++
        "dbf7c672e156d6cc253b833df1dd69b1b04e751f0f" ++
        "002b00020304";

    // // 2-1. append server hello to stream
    // var i_stream = streams.getPtr(.initial);
    // try i_stream.reciever.push(try allocParseHex(raw_sh_hex), 0);

    // 2-2. handle stream
    var raw_sh_bytes = try allocParseHex(raw_sh_hex);
    defer allocator.free(raw_sh_bytes);
    try client.doHandshake(raw_sh_bytes);

    // 2-3. test
    // 2-3-1. check input data successfully
    try testing.expectEqual(raw_sh_hex.len / 2, client.raw_sh.?.max_len);
    try testing.expectFmt(
        raw_sh_hex,
        "{s}",
        .{fmt.fmtSliceHexLower(client.raw_sh.?.data.items)},
    );
    try testing.expectEqualSlices(
        u8,
        "\xc9\x82\x88\x76\x11\x20\x95\xfe\x66\x76\x2b\xdb\xf7\xc6\x72\xe1\x56\xd6\xcc\x25\x3b\x83\x3d\xf1\xdd\x69\xb1\xb0\x4e\x75\x1f\x0f",
        &client.x25519_peer.?,
    );

    // 2-3-2. check derive keys successfully
    // early secret
    try testing.expectFmt(
        "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a",
        "{s}",
        .{fmt.fmtSliceHexLower(&client.early_secret.?)},
    );
    // handshake secret
    try testing.expectFmt(
        "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac",
        "{s}",
        .{fmt.fmtSliceHexLower(&client.handshake_secret.?)},
    );
    // client handshake traffic secret
    try testing.expectFmt(
        "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21",
        "{s}",
        .{fmt.fmtSliceHexLower(&client.client_handshake.?.secret)},
    );
    // server handshake traffic secret
    try testing.expectFmt(
        "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38",
        "{s}",
        .{fmt.fmtSliceHexLower(&client.server_handshake.?.secret)},
    );

    // 3. recieve encryted extensions, certificate, certificate verify, finished
    const raw_ee_hex =
        "080000240022000a00140012001d0017" ++
        "0018001901000101010201030104001c" ++
        "0002400100000000";
    const raw_cert_hex =
        "0b0001b9000001b50001b0308201ac30" ++
        "820115a003020102020102300d06092a" ++
        "864886f70d01010b0500300e310c300a" ++
        "06035504031303727361301e170d3136" ++
        "303733303031323335395a170d323630" ++
        "3733303031323335395a300e310c300a" ++
        "0603550403130372736130819f300d06" ++
        "092a864886f70d010101050003818d00" ++
        "30818902818100b4bb498f8279303d98" ++
        "0836399b36c6988c0c68de55e1bdb826" ++
        "d3901a2461eafd2de49a91d015abbc9a" ++
        "95137ace6c1af19eaa6af98c7ced4312" ++
        "0998e187a80ee0ccb0524b1b018c3e0b" ++
        "63264d449a6d38e22a5fda4308467480" ++
        "30530ef0461c8ca9d9efbfae8ea6d1d0" ++
        "3e2bd193eff0ab9a8002c47428a6d35a" ++
        "8d88d79f7f1e3f0203010001a31a3018" ++
        "30090603551d1304023000300b060355" ++
        "1d0f0404030205a0300d06092a864886" ++
        "f70d01010b05000381810085aad2a0e5" ++
        "b9276b908c65f73a7267170618a54c5f" ++
        "8a7b337d2df7a594365417f2eae8f8a5" ++
        "8c8f8172f9319cf36b7fd6c55b80f21a" ++
        "03015156726096fd335e5e67f2dbf102" ++
        "702e608ccae6bec1fc63a42a99be5c3e" ++
        "b7107c3c54e9b9eb2bd5203b1c3b84e0" ++
        "a8b2f759409ba3eac9d91d402dcc0cc8" ++
        "f8961229ac9187b42b4de10000";
    const raw_cv_hex =
        "0f000084080400805a747c5d88fa9bd2" ++
        "e55ab085a61015b7211f824cd484145a" ++
        "b3ff52f1fda8477b0b7abc90db78e2d3" ++
        "3a5c141a078653fa6bef780c5ea248ee" ++
        "aaa785c4f394cab6d30bbe8d4859ee51" ++
        "1f602957b15411ac027671459e46445c" ++
        "9ea58c181e818e95b8c3fb0bf3278409" ++
        "d3be152a3da5043e063dda65cdf5aea2" ++
        "0d53dfacd42f74f3";
    const raw_sfin_hex =
        "140000209b9b141d906337fbd2cbdce7" ++
        "1df4deda4ab42c309572cb7fffee5454" ++
        "b78f0718";

    var raw_ee_bytes = try allocParseHex(raw_ee_hex);
    defer allocator.free(raw_ee_bytes);
    var raw_cert_bytes = try allocParseHex(raw_cert_hex);
    defer allocator.free(raw_cert_bytes);
    var raw_cv_bytes = try allocParseHex(raw_cv_hex);
    defer allocator.free(raw_cv_bytes);
    var raw_sfin_bytes = try allocParseHex(raw_sfin_hex);
    defer allocator.free(raw_sfin_bytes);

    // // 3-1. append these bytes to handshake stream
    // var h_stream = streams.getPtr(.handshake);
    // var offset: usize = 0;
    // try h_stream.reciever.push(try allocParseHex(raw_ee_hex), offset);
    // offset += raw_ee_hex.len / 2;
    // try h_stream.reciever.push(try allocParseHex(raw_cert_hex), offset);
    // offset += raw_cert_hex.len / 2;
    // try h_stream.reciever.push(try allocParseHex(raw_cv_hex), offset);
    // offset += raw_cv_hex.len / 2;
    // try h_stream.reciever.push(try allocParseHex(raw_sfin_hex), offset);
    // offset += raw_sfin_hex.len / 2;

    // 3-2. handle stream
    try client.doHandshake(raw_ee_bytes);
    try client.doHandshake(raw_cert_bytes);
    try client.doHandshake(raw_cv_bytes);
    try client.doHandshake(raw_sfin_bytes);

    // 3-3. test
    // 3-3-1. check input data successfully
    try testing.expectEqual(raw_ee_bytes.len, client.raw_ee.?.max_len);
    try testing.expectEqual(raw_cert_bytes.len, client.raw_cert.?.max_len);
    try testing.expectEqual(raw_cv_bytes.len, client.raw_cv.?.max_len);
    try testing.expectEqual(raw_sfin_bytes.len, client.raw_sfin.?.max_len);
    try testing.expectFmt(
        raw_ee_hex,
        "{s}",
        .{fmt.fmtSliceHexLower(client.raw_ee.?.data.items)},
    );
    try testing.expectFmt(
        raw_cert_hex,
        "{s}",
        .{fmt.fmtSliceHexLower(client.raw_cert.?.data.items)},
    );
    try testing.expectFmt(
        raw_cv_hex,
        "{s}",
        .{fmt.fmtSliceHexLower(client.raw_cv.?.data.items)},
    );
    try testing.expectFmt(
        raw_sfin_hex,
        "{s}",
        .{fmt.fmtSliceHexLower(client.raw_sfin.?.data.items)},
    );

    // 3-3-2. check derive keys successfully
    // Master Secret
    try testing.expectFmt(
        "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919",
        "{s}",
        .{fmt.fmtSliceHexLower(&client.master_secret.?)},
    );
    // client application traffic secret
    try testing.expectFmt(
        "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5",
        "{s}",
        .{fmt.fmtSliceHexLower(&client.client_master.?.secret)},
    );
    // server application traffic secret
    try testing.expectFmt(
        "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643",
        "{s}",
        .{fmt.fmtSliceHexLower(&client.server_master.?.secret)},
    );

    // 3-3-3. derive finished successfully
    var buf = dummy_stream.stream.getWritten();
    try testing.expectFmt(
        "14000020a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61",
        "{s}",
        .{fmt.fmtSliceHexLower(buf)},
    );
}

const std = @import("std");
const io = std.io;

const Epoch = @import("provider.zig").Epoch;
const q_crypto = @import("../crypto.zig");
const AeadAbst = q_crypto.AeadAbst;
const HkdfAbst = q_crypto.HkdfAbst;

pub const QuicApi = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    const Self = @This();

    pub const Error = error{WriteCryptoStreamFailed};

    pub const Writer = io.Writer(IoContext, Error, writeWithCtx);

    pub const IoContext = struct {
        ptr: *Self,
        epoch: Epoch,
    };

    pub const VTable = struct {
        setReadSecret: *const fn (ptr: *anyopaque, epoch: Epoch, aead: AeadAbst, hkdf: HkdfAbst, secret: []const u8) void,
        setWriteSecret: *const fn (ptr: *anyopaque, epoch: Epoch, aead: AeadAbst, hkdf: HkdfAbst, secret: []const u8) void,
        writeHandshakeData: *const fn (ptr: *anyopaque, epoch: Epoch, data: []const u8) Error!usize,
    };

    pub fn init(
        pointer: anytype,
        comptime setReadSecretFn: fn (ptr: @TypeOf(pointer), epoch: Epoch, aead: AeadAbst, hkdf: HkdfAbst, secret: []const u8) void,
        comptime setWriteSecretFn: fn (ptr: @TypeOf(pointer), epoch: Epoch, aead: AeadAbst, hkdf: HkdfAbst, secret: []const u8) void,
        comptime writeHandshakeDataFn: fn (ptr: @TypeOf(pointer), epoch: Epoch, data: []const u8) Error!usize,
    ) Self {
        const Ptr = @TypeOf(pointer);
        const ptr_info = @typeInfo(Ptr);

        std.debug.assert(ptr_info == .Pointer); // Must be a pointer
        std.debug.assert(ptr_info.Pointer.size == .One); // Must be a single-item pointer

        const alignment = ptr_info.Pointer.alignment;

        const Gen = struct {
            pub fn setReadSecretImpl(ptr: *anyopaque, epoch: Epoch, aead: AeadAbst, hkdf: HkdfAbst, secret: []const u8) void {
                const self = @ptrCast(Ptr, @alignCast(alignment, ptr));
                return @call(
                    .{ .modifier = .always_inline },
                    setReadSecretFn,
                    .{ self, epoch, aead, hkdf, secret },
                );
            }

            pub fn setWriteSecretImpl(ptr: *anyopaque, epoch: Epoch, aead: AeadAbst, hkdf: HkdfAbst, secret: []const u8) void {
                const self = @ptrCast(Ptr, @alignCast(alignment, ptr));
                return @call(
                    .{ .modifier = .always_inline },
                    setWriteSecretFn,
                    .{ self, epoch, aead, hkdf, secret },
                );
            }

            pub fn writeHandshakeDataImpl(ptr: *anyopaque, epoch: Epoch, data: []const u8) Error!usize {
                const self = @ptrCast(Ptr, @alignCast(alignment, ptr));
                return @call(
                    .{ .modifier = .always_inline },
                    writeHandshakeDataFn,
                    .{ self, epoch, data },
                );
            }

            pub const vtable = VTable{
                .setReadSecret = setReadSecretImpl,
                .setWriteSecret = setWriteSecretImpl,
                .writeHandshakeData = writeHandshakeDataImpl,
            };
        };

        return Self{
            .ptr = pointer,
            .vtable = &Gen.vtable,
        };
    }

    pub fn setReadSecret(self: *Self, epoch: Epoch, aead: AeadAbst, hkdf: HkdfAbst, secret: []const u8) void {
        self.vtable.setReadSecret(self.ptr, epoch, aead, hkdf, secret);
    }

    pub fn setWriteSecret(self: *Self, epoch: Epoch, aead: AeadAbst, hkdf: HkdfAbst, secret: []const u8) void {
        self.vtable.setReadSecret(self.ptr, epoch, aead, hkdf, secret);
    }

    pub fn writeHandshakeData(self: *Self, epoch: Epoch, data: []const u8) Error!usize {
        return self.vtable.writeHandshakeData(self.ptr, epoch, data);
    }

    pub fn writeWithCtx(ctx: IoContext, data: []const u8) Error!usize {
        return ctx.ptr.writeHandshakeData(ctx.epoch, data);
    }

    pub fn getWriter(self: *Self, epoch: Epoch) Writer {
        var ctx = IoContext{ .ptr = self, .epoch = epoch };
        return Writer{ .context = ctx };
    }
};

const std = @import("std");
const io = std.io;

const Epoch = @import("provider.zig").Epoch;
const q_crypto = @import("../crypto.zig");
const AeadAbst = q_crypto.AeadAbst;
const HkdfAbst = q_crypto.HkdfAbst;

pub fn QuicApi(
    comptime ApiError: type,
) type {
    return struct {
        ptr: *anyopaque,
        vtable: *const VTable,

        const Self = @This();

        pub const Error = ApiError;

        pub const Writer = io.Writer(IoContext, ApiError, writeWithCtx);

        pub const IoContext = struct {
            ptr: *Self,
            epoch: Epoch,
        };

        pub const VTable = struct {
            setReadSecret: *const fn (ptr: *anyopaque, epoch: Epoch, aead: AeadAbst, hkdf: HkdfAbst, secret: []const u8) void,
            setWriteSecret: *const fn (ptr: *anyopaque, epoch: Epoch, aead: AeadAbst, hkdf: HkdfAbst, secret: []const u8) void,
            writeHandshakeData: *const fn (ptr: *anyopaque, epoch: Epoch, data: []const u8) ApiError!usize,
        };

        pub fn setReadSecret(self: *Self, epoch: Epoch, aead: AeadAbst, hkdf: HkdfAbst, secret: []const u8) void {
            self.vtable.setReadSecret(self.ptr, epoch, aead, hkdf, secret);
        }

        pub fn setWriteSecret(self: *Self, epoch: Epoch, aead: AeadAbst, hkdf: HkdfAbst, secret: []const u8) void {
            self.vtable.setReadSecret(self.ptr, epoch, aead, hkdf, secret);
        }

        pub fn writeHandshakeData(self: *Self, epoch: Epoch, data: []const u8) ApiError!usize {
            return self.vtable.writeHandshakeData(self.ptr, epoch, data);
        }

        pub fn writeWithCtx(ctx: IoContext, data: []const u8) ApiError!usize {
            return ctx.ptr.writeHandshakeData(ctx.epoch, data);
        }

        pub fn getWriter(self: *Self, epoch: Epoch) Writer {
            var ctx = IoContext{ .ptr = self, .epoch = epoch };
            return Writer{ .context = ctx };
        }
    };
}

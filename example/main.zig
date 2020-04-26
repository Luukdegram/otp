const std = @import("std");
const otp = @import("otp");
const warn = std.debug.warn;

pub fn main() !void {
    const hotp = otp.Hotp.init();
    const code = try hotp.generateCode("secretkey", 0);
    warn("code: {}\n", .{code});

    const totp = otp.Totp.init(otp.Options{});
    warn("\ncode: {}\n", .{try totp.generateCode("secretkey", std.time.timestamp())});
}

const std = @import("std");
const otp = @import("otp");
const print = std.debug.print;

pub fn main() !void {
    const hotp = otp.Hotp.init();
    const code = try hotp.generateCode("secretkey", 0);
    print("code: {}\n", .{code});

    const totp = otp.Totp.init(otp.Options{});
    const totp_code = try totp.generateCode("secretkey", std.time.timestamp());
    print("code: {}\n", .{totp_code});
}

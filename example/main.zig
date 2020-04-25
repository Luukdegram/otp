const std = @import("std");
const otp = @import("otp");
const warn = std.debug.warn;

pub fn main() !void {
    const hotp = otp.Hotp.init("1234");
    warn("code: {}\n", .{hotp.generateCode(0, 6)});
}

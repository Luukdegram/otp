const builtin = @import("builtin");
const std = @import("std");
const crypto = std.crypto;

/// Possible errors when generating a code
pub const CodeGenError = error{
    /// OutOfBounds is triggered when digits is smaller than 6 or higher than 8.
    OutOfBounds,
    /// UnsupportedAlgorithm is triggered when an algorithm is passed of which is not supported.
    UnsupportedAlgorithm,
};

/// Supported hashing algorithms for generating an OTP.
/// Currently `Sha1` and `Sha256` are supported.
pub const Algorithm = enum {
    Sha1,
    Sha256,
};

/// Options can be provided to Totp to generate a code dependent on
/// the give `digits`, `algorithm` and `time_step`.
pub const Options = struct {
    digits: u8 = 6,
    algorithm: Algorithm = .Sha1,
    time_step: u8 = 30,
};

/// Hotp is a counter-based One Time password generator.
/// It implements `rfc4226` which can be found at
/// https://tools.ietf.org/html/rfc4226
pub const Hotp = struct {
    const Self = @This();

    digits: u8 = 6,

    /// Init creates a new Hotp struct with the `digits` set by default to 6.
    pub fn init() Self {
        return .{};
    }

    /// generateCode creates a new code using the given secret.
    /// The counter needs to be synchronized between the client and server.
    /// It is up to the implementation to handle the synchronization, this library does not facilitate it.
    pub fn generateCode(self: Self, secret: []const u8, counter: u64) ![]u8 {
        return buildCode(secret, counter, self.digits, Algorithm.Sha1);
    }
};

/// Totp is a time-based One Time Password generator.
/// It implements `rfc6238` which can be found at
/// https://tools.ietf.org/html/rfc6238
pub const Totp = struct {
    const Self = @This();

    opts: Options,

    /// Init creates a new Totp struct and handles the generated codes according to it.
    pub fn init(opts: Options) Self {
        return .{ .opts = opts };
    }

    /// generateCode creates a new code with a length of `digits`.
    /// `timestamp` can be generated using `std.milliTimestamp`.
    pub fn generateCode(self: Self, secret: []const u8, time: i64) ![]u8 {
        // Convert to floats for higher precision
        const counter = @intToFloat(f64, @bitCast(u64, time)) / @intToFloat(f64, self.opts.time_step);
        return buildCode(secret, @floatToInt(u64, std.math.floor(counter)), self.opts.digits, self.opts.algorithm);
    }
};

/// generateCode creates the actual code given the provided parameters from the `Hotp` & `Totp` structs.
fn buildCode(secret: []const u8, counter: u64, digits: u8, algorithm: Algorithm) ![]u8 {
    if (digits < 6 or digits > 8) {
        return CodeGenError.OutOfBounds;
    }

    var buf: []u8 = undefined;

    switch (algorithm) {
        .Sha1 => {
            const hmac = crypto.HmacSha1;
            var buffer: [hmac.mac_length]u8 = undefined;
            var ctx = hmac.init(secret);
            ctx.update(intToSlice(counter));
            ctx.final(buffer[0..]);
            buf = buffer[0..buffer.len];
        },
        .Sha256 => {
            const hmac = crypto.HmacSha256;
            var buffer: [hmac.mac_length]u8 = undefined;
            var ctx = hmac.init(secret);
            ctx.update(intToSlice(counter));
            ctx.final(buffer[0..]);
            buf = buffer[0..buffer.len];
        },
        else => {
            return CodeGenError.UnsupportedAlgorithm;
        },
    }

    // Truncate HS (HS = Hmac(key, counter))
    // https://tools.ietf.org/html/rfc4226#section-5.4
    const offset = buf[buf.len - 1] & 0xf;
    const bin_code: u32 = @as(u32, (buf[offset] & 0x7f)) << 24 |
        @as(u32, (buf[offset + 1] & 0xff)) << 16 |
        @as(u32, (buf[offset + 2] & 0xff)) << 8 |
        @as(u32, (buf[offset + 3] & 0xff));

    // add padding to the left incase the first number is a 0
    const code = bin_code % std.math.pow(u32, 10, digits);
    return formatCode(code, digits);
}

/// Creates a byte slice from the given integer
fn intToSlice(val: u64) []const u8 {
    var bytes: [8]u8 = undefined;
    std.mem.writeIntBig(u64, &bytes, val);
    return bytes[0..];
}

/// formatCode will try to parse the integer and return a string.
/// An extra `0` will be added to the left to match the given length.
fn formatCode(val: u64, length: u8) []u8 {
    var buf: [8]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    std.fmt.formatIntValue(val, "", std.fmt.FormatOptions{ .width = length, .fill = '0' }, fbs.outStream()) catch unreachable;
    return fbs.getWritten();
}

test "HOTP code generation" {
    const hotp = Hotp.init();
    const code = try hotp.generateCode("secretkey", 0);
    std.testing.expectEqualSlices(u8, "049381", code);
}

test "HOTP 8 digits" {
    var hotp = Hotp.init();
    hotp.digits = 8;
    const code = try hotp.generateCode("secretkey", 0);
    std.testing.expectEqualSlices(u8, "74049381", code);
}

test "HOTP different counters" {
    const hotp = Hotp.init();
    var code = try hotp.generateCode("secretkey", 1);
    std.testing.expectEqualSlices(u8, "534807", code);

    code = try hotp.generateCode("secretkey", 2);
    std.testing.expectEqualSlices(u8, "155320", code);

    code = try hotp.generateCode("secretkey", 3);
    std.testing.expectEqualSlices(u8, "642297", code);

    code = try hotp.generateCode("secretkey", 4);
    std.testing.expectEqualSlices(u8, "964223", code);

    code = try hotp.generateCode("secretkey", 5);
    std.testing.expectEqualSlices(u8, "416848", code);
}

test "TOTP code generation" {
    const totp = Totp.init(Options{});
    const time = 1587915766;
    const code = try totp.generateCode("secretkey", time);
    std.testing.expectEqualSlices(u8, "623043", code);
}

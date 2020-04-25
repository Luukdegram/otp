const builtin = @import("builtin");
const std = @import("std");
const warn = std.debug.warn;
const crypto = std.crypto;

/// Hotp is a counter-based One Time password generator.
/// It implements `rfc4226` which can be found at
/// https://tools.ietf.org/html/rfc4226
pub const Hotp = struct {
    secret: []const u8,

    /// Init creates a new Hotp struct and assigns the given secret.
    /// The `secret` parameter expects the actual decoded key, rather than a base32 encoded string.
    /// Base32 is not part of the specs.
    pub fn init(secret: []const u8) Hotp {
        return Hotp{ .secret = secret };
    }

    /// generateCode creates a new code with a length of `digits`.
    /// The counter needs to be synchronized between the client and server.
    /// It is up to the implementation to handle the synchronization, this library does not facilitate it.
    pub fn generateCode(self: Hotp, counter: u64, digits: u8) []u8 {
        return buildCode(self.secret, counter, digits, crypto.Sha1);
    }
};

/// Totp is a time-based One Time Password generator.
/// It implements `rfc6238` which can be found at
/// https://tools.ietf.org/html/rfc6238
pub const Totp = struct {
    secret: []const u8,

    /// Init creates a new Totp struct and assigns the given secret.
    /// The `secret` parameter expects the actual decoded key, rather than a base32 encoded string.
    /// Base32 is not part of the specs.
    pub fn init(secret: []const u8) Totp {
        return Totp{ .secret = secret };
    }

    /// generateCode creates a new code with a length of `digits`.
    /// `timestamp` can be generated using `std.milliTimestamp`.
    pub fn generateCode(self: Totp, timestamp: u64, digits: u8, algorithm: crypto.Hash) []u8 {}
};

/// generateCode creates the actual code given the provided parameters from the `Hotp` & `Totp` structs.
fn buildCode(secret: []const u8, counter: u64, digits: u8, algorithm: var) []u8 {
    const hmac = crypto.HmacSha1;
    var out: [hmac.mac_length]u8 = undefined;

    var ctx = hmac.init(secret[0..]);
    ctx.update(intToSlice(counter));
    ctx.final(out[0..]);

    // Truncate HS (HS = Hmac(key, counter))
    // https://tools.ietf.org/html/rfc4226#section-5.4
    const offset = out[hmac.mac_length - 1] & 0xf;
    const bin_code: u32 = @as(u32, (out[offset] & 0x7f)) << 24 |
        @as(u32, (out[offset + 1] & 0xff)) << 16 |
        @as(u32, (out[offset + 2] & 0xff)) << 8 |
        @as(u32, (out[offset + 3] & 0xff));

    // add padding to the left incase the first number is a 0
    const code = bin_code & std.math.pow(u32, 10, digits);
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
fn formatCode(val: u64, comptime length: u8) []u8 {
    var buf: [length]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try formatIntValue(val, "", FormatOptions{ .width = length, .fill = '0' }, fbs.outStream());

    return fbs.getWritten();
}

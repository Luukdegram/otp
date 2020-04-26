<!--
 Copyright (c) 2020 Luuk de Gram
 
 This software is released under the MIT License.
 https://opensource.org/licenses/MIT
-->

# OTP

OTP is a one-time-password library supporting both HOTP and TOTP according to [`RFC 4226`](https://tools.ietf.org/html/rfc4226) and [`RFC 6238`](https://tools.ietf.org/html/rfc6238), written in [Zig](https://ziglang.org) version *0.6.0*.

Currently only the generation of codes is supported. Verification has to be done by the implementation.

**note:**
This library's primary goal was to get more familair with the Zig lange.

## Example
```zig
const std = @import("std");
const otp = @import("otp");
const warn = std.debug.warn;

pub fn main() !void {
    const hotp = otp.Hotp.init();
    const code = try hotp.generateCode("secretkey", 0);
    warn("code: {}\n", .{code});
}
```
You can use the `build.zig` file as reference point on how to link the library to your own project.

### Tests
You can run the tests using the following command
```
zig build test
```

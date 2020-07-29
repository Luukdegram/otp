const std = @import("std");
const Builder = std.build.Builder;

pub fn build(b: *Builder) void {
    const mode = b.standardReleaseOptions();
    const lib = b.addStaticLibrary("otp", "src/otp.zig");
    lib.setBuildMode(mode);
    lib.install();

    var main_tests = b.addTest("src/otp.zig");
    main_tests.setBuildMode(mode);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests.step);

    const example = b.addExecutable("example", "example" ++ std.fs.path.sep_str ++ "main.zig");
    example.addPackagePath("otp", "src/otp.zig");
    example.setBuildMode(mode);
    example.install();

    const run_example = example.run();
    run_example.step.dependOn(b.getInstallStep());

    const example_step = b.step("example", "Run example");
    example_step.dependOn(&run_example.step);
}

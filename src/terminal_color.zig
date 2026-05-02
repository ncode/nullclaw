const std = @import("std");
const std_compat = @import("compat");
const builtin = @import("builtin");

extern "kernel32" fn GetStdHandle(nStdHandle: std.os.windows.DWORD) callconv(.winapi) ?std.os.windows.HANDLE;
extern "kernel32" fn GetConsoleMode(
    hConsoleHandle: std.os.windows.HANDLE,
    lpMode: *std.os.windows.DWORD,
) callconv(.winapi) std.os.windows.BOOL;
extern "kernel32" fn SetConsoleMode(
    hConsoleHandle: std.os.windows.HANDLE,
    dwMode: std.os.windows.DWORD,
) callconv(.winapi) std.os.windows.BOOL;
const STD_OUTPUT_HANDLE: std.os.windows.DWORD = @bitCast(@as(i32, -11));

pub const Color = struct {
    pub const reset = "\x1b[0m";
    pub const green = "\x1b[32m";
    pub const yellow = "\x1b[33m";
    pub const red = "\x1b[31m";
};

pub fn shouldColorize(file: std_compat.fs.File) bool {
    // Respect NO_COLOR convention (https://no-color.org/)
    if (comptime builtin.os.tag != .windows and builtin.link_libc) {
        if (std.c.getenv("NO_COLOR")) |_| return false;
    }

    // Never colorize if stdout is redirected to a file/pipe.
    if (!file.isTty()) return false;

    // On Windows, attempt to enable Virtual Terminal Processing.
    // If that fails, fall back to no color.
    if (builtin.os.tag == .windows) {
        return enableWindowsVT100() catch false;
    }

    return true;
}

/// Windows-specific: enable ENABLE_VIRTUAL_TERMINAL_PROCESSING on stdout.
fn enableWindowsVT100() !bool {
    const windows = std.os.windows;
    const handle = GetStdHandle(STD_OUTPUT_HANDLE) orelse return false;
    var mode: windows.DWORD = 0;
    if (GetConsoleMode(handle, &mode) == .FALSE) return false;
    mode |= 0x0004; // ENABLE_VIRTUAL_TERMINAL_PROCESSING
    return SetConsoleMode(handle, mode) != .FALSE;
}

test "Color exposes shared ANSI status colors" {
    try std.testing.expectEqualStrings("\x1b[0m", Color.reset);
    try std.testing.expectEqualStrings("\x1b[32m", Color.green);
    try std.testing.expectEqualStrings("\x1b[33m", Color.yellow);
    try std.testing.expectEqualStrings("\x1b[31m", Color.red);
}

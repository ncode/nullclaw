const std = @import("std");
const root = @import("root.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;
const isPathSafe = @import("path_security.zig").isPathSafe;
const isResolvedPathAllowed = @import("path_security.zig").isResolvedPathAllowed;
const generateLineHash = @import("file_read_hashed.zig").generateLineHash;

/// Default maximum file size to read (10MB).
const DEFAULT_MAX_FILE_SIZE: usize = 10 * 1024 * 1024;

const Target = struct {
    line_num: usize,
    hash: []const u8,

    fn parse(input: []const u8) !Target {
        if (!std.mem.startsWith(u8, input, "L")) return error.InvalidFormat;
        const colon = std.mem.indexOfScalar(u8, input, ':') orelse return error.InvalidFormat;
        const line_num = try std.fmt.parseInt(usize, input[1..colon], 10);
        const hash = input[colon + 1 ..];
        if (hash.len != 3) return error.InvalidHashLength;
        return .{ .line_num = line_num, .hash = hash };
    }
};

/// Edit file contents using Hashline anchors for verifiable changes.
pub const FileEditHashedTool = struct {
    workspace_dir: []const u8,
    allowed_paths: []const []const u8 = &.{},
    max_file_size: usize = DEFAULT_MAX_FILE_SIZE,

    pub const tool_name = "file_edit_hashed";
    pub const tool_description = "Replace lines in a file using Hashline anchors to ensure edit integrity";
    pub const tool_params =
        \\{"type":"object","properties":{"path":{"type":"string","description":"Relative path to the file"},"target":{"type":"string","description":"The Hashline tag to replace (e.g. L10:abc)"},"end_target":{"type":"string","description":"Optional end tag for range replacement (e.g. L15:def)"},"new_text":{"type":"string","description":"The new content to insert"}},"required":["path","target","new_text"]}
    ;

    const vtable = root.ToolVTable(@This());

    pub fn tool(self: *FileEditHashedTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    pub fn execute(self: *FileEditHashedTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const path = root.getString(args, "path") orelse return ToolResult.fail("Missing 'path'");
        const target_str = root.getString(args, "target") orelse return ToolResult.fail("Missing 'target'");
        const end_target_str = root.getString(args, "end_target");
        const new_text = root.getString(args, "new_text") orelse return ToolResult.fail("Missing 'new_text'");

        const target = Target.parse(target_str) catch return ToolResult.fail("Invalid target format. Use L<num>:<hash>");
        const end_target = if (end_target_str) |s| Target.parse(s) catch return ToolResult.fail("Invalid end_target format") else null;

        const full_path = if (std.fs.path.isAbsolute(path)) blk: {
            if (self.allowed_paths.len == 0) return ToolResult.fail("Absolute paths not allowed");
            break :blk try allocator.dupe(u8, path);
        } else blk: {
            if (!isPathSafe(path)) return ToolResult.fail("Path not allowed");
            break :blk try std.fs.path.join(allocator, &.{ self.workspace_dir, path });
        };
        defer allocator.free(full_path);

        const resolved = try std.fs.cwd().realpathAlloc(allocator, full_path);
        defer allocator.free(resolved);

        const file = try std.fs.openFileAbsolute(resolved, .{});
        const contents = try file.readToEndAlloc(allocator, self.max_file_size);
        file.close();
        defer allocator.free(contents);

        var lines: std.ArrayList([]const u8) = .{};
        defer lines.deinit(allocator);
        var line_it = std.mem.splitScalar(u8, contents, '\n');
        while (line_it.next()) |line| try lines.append(allocator, line);

        if (target.line_num == 0 or target.line_num > lines.items.len) return ToolResult.fail("Target line number out of range");
        
        // Verify start line hash
        const current_start_hash = generateLineHash(lines.items[target.line_num - 1]);
        if (!std.mem.eql(u8, &current_start_hash, target.hash)) {
            const msg = try std.fmt.allocPrint(allocator, "Hash mismatch at line {d}. Expected {s}, found {s}. The file may have changed.", .{ target.line_num, target.hash, current_start_hash });
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        }

        const end_line_idx = if (end_target) |et| blk: {
            if (et.line_num < target.line_num or et.line_num > lines.items.len) return ToolResult.fail("End target out of range");
            const current_end_hash = generateLineHash(lines.items[et.line_num - 1]);
            if (!std.mem.eql(u8, &current_end_hash, et.hash)) {
                return ToolResult.fail("Hash mismatch at end line");
            }
            break :blk et.line_num;
        } else target.line_num;

        // Build new content
        var output: std.ArrayList(u8) = .{};
        defer output.deinit(allocator);

        for (lines.items, 1..) |line, i| {
            if (i == target.line_num) {
                try output.appendSlice(allocator, new_text);
                if (!std.mem.endsWith(u8, new_text, "\n")) try output.append(allocator, '\n');
            } else if (i > target.line_num and i <= end_line_idx) {
                // Skip these lines as they are replaced by the range
                continue;
            } else {
                try output.appendSlice(allocator, line);
                if (i < lines.items.len or std.mem.endsWith(u8, contents, "\n")) {
                     try output.append(allocator, '\n');
                }
            }
        }

        const out_file = try std.fs.createFileAbsolute(resolved, .{ .truncate = true });
        defer out_file.close();
        try out_file.writeAll(output.items);

        return ToolResult.ok("File updated successfully using Hashline verification");
    }
};

// ── Tests ───────────────────────────────────────────────────────────

test "file_edit_hashed replaces line when hash matches" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const content = "line one\nline two\nline three";
    try tmp_dir.dir.writeFile(.{ .sub_path = "test.txt", .data = content });
    const ws_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    const h2 = generateLineHash("line two");
    var args_buf: [128]u8 = undefined;
    const args = try std.fmt.bufPrint(&args_buf, "{{\"path\": \"test.txt\", \"target\": \"L2:{s}\", \"new_text\": \"NEW LINE\"}}", .{h2});

    var ft = FileEditHashedTool{ .workspace_dir = ws_path };
    const parsed = try root.parseTestArgs(args);
    defer parsed.deinit();

    const result = try ft.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(result.success);

    const updated = try tmp_dir.dir.readFileAlloc(std.testing.allocator, "test.txt", 1024);
    defer std.testing.allocator.free(updated);
    try std.testing.expect(std.mem.indexOf(u8, updated, "NEW LINE") != null);
    try std.testing.expect(std.mem.indexOf(u8, updated, "line two") == null);
}

test "file_edit_hashed fails when hash mismatches" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try tmp_dir.dir.writeFile(.{ .sub_path = "test.txt", .data = "wrong content" });
    const ws_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    var ft = FileEditHashedTool{ .workspace_dir = ws_path };
    const parsed = try root.parseTestArgs("{\"path\": \"test.txt\", \"target\": \"L1:abc\", \"new_text\": \"data\"}");
    defer parsed.deinit();

    const result = try ft.execute(std.testing.allocator, parsed.value.object);
    defer if (result.error_msg) |em| std.testing.allocator.free(em);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "Hash mismatch") != null);
}

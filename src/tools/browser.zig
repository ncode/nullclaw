const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;
const net_security = @import("../root.zig").net_security;
const http_util = @import("../http_util.zig");

/// Maximum response body size for the "read" action (8 KB).
const MAX_READ_BYTES: usize = 8192;
/// Maximum raw fetch size for page reads (64 KB, then truncated to MAX_READ_BYTES).
const MAX_FETCH_BYTES: usize = 65536;
const MAX_READ_REDIRECTS: usize = 3;

/// Browser tool — opens URLs in the system browser and fetches page content.
/// Supports "open" (launch URL), "read" (fetch body natively), and returns
/// informative errors for CDP-only actions (click, type, scroll, screenshot).
pub const BrowserTool = struct {
    pub const tool_name = "browser";
    pub const tool_description = "Browse web pages. Actions: open, screenshot, click, type, scroll, read.";
    pub const tool_params =
        \\{"type":"object","properties":{"action":{"type":"string","enum":["open","screenshot","click","type","scroll","read"],"description":"Browser action to perform"},"url":{"type":"string","description":"URL to open"},"selector":{"type":"string","description":"CSS selector for click/type"},"text":{"type":"string","description":"Text to type"}},"required":["action"]}
    ;

    const vtable = root.ToolVTable(@This());

    pub fn tool(self: *BrowserTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    pub fn execute(_: *BrowserTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const action = root.getString(args, "action") orelse
            return ToolResult.fail("Missing 'action' parameter");

        if (std.mem.eql(u8, action, "open")) {
            return executeOpen(allocator, args);
        } else if (std.mem.eql(u8, action, "read")) {
            return executeRead(allocator, args);
        } else if (std.mem.eql(u8, action, "screenshot")) {
            return ToolResult.fail("Use the screenshot tool instead");
        } else if (std.mem.eql(u8, action, "click") or
            std.mem.eql(u8, action, "type") or
            std.mem.eql(u8, action, "scroll"))
        {
            const msg = try std.fmt.allocPrint(
                allocator,
                "Browser action '{s}' requires CDP (Chrome DevTools Protocol) which is not available. Use 'open' to launch in system browser or 'read' to fetch page content.",
                .{action},
            );
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        } else {
            const msg = try std.fmt.allocPrint(allocator, "Unknown browser action '{s}'", .{action});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        }
    }

    /// "open" — launch URL in the platform's default browser.
    fn executeOpen(allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const url = root.getString(args, "url") orelse
            return ToolResult.fail("Missing 'url' parameter for open action");

        if (!std.mem.startsWith(u8, url, "https://")) {
            return ToolResult.fail("Only https:// URLs are supported for security");
        }

        // On Windows cmd.exe /c start interprets shell metacharacters in the URL.
        // On Unix, open/xdg-open receives the URL as a separate argv element (execvp),
        // so metacharacters like & (query params) and % (percent-encoding) are safe.
        if (comptime builtin.os.tag == .windows) {
            for (url) |c| {
                if (c == '&' or c == '|' or c == ';' or c == '"' or c == '\'' or
                    c == '<' or c == '>' or c == '`' or c == '(' or c == ')' or
                    c == '^' or c == '%' or c == '!' or c == '\n' or c == '\r')
                {
                    return ToolResult.fail("URL contains shell metacharacters — open manually for safety");
                }
            }
        }

        // In test mode, skip actual browser spawn to avoid opening windows during CI/tests.
        if (builtin.is_test) {
            const msg = try std.fmt.allocPrint(allocator, "Opened {s} in system browser", .{url});
            return ToolResult{ .success = true, .output = msg };
        }

        const proc = @import("process_util.zig");
        const argv: []const []const u8 = if (comptime builtin.os.tag == .windows)
            &.{ "cmd.exe", "/c", "start", url }
        else
            &.{ comptime if (builtin.os.tag == .macos) "open" else "xdg-open", url };

        const result = proc.run(allocator, argv, .{ .max_output_bytes = 4096 }) catch {
            return ToolResult.fail("Failed to spawn browser open command");
        };
        result.deinit(allocator);

        if (!result.success) {
            if (result.exit_code) |code| {
                const msg = try std.fmt.allocPrint(allocator, "Browser open command exited with code {d}", .{code});
                return ToolResult{ .success = false, .output = "", .error_msg = msg };
            }
            return ToolResult{ .success = false, .output = "", .error_msg = "Browser open command terminated by signal" };
        }

        const msg = try std.fmt.allocPrint(allocator, "Opened {s} in system browser", .{url});
        return ToolResult{ .success = true, .output = msg };
    }

    /// "read" — fetch URL content and return body text (truncated to 8 KB).
    fn executeRead(allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const url = root.getString(args, "url") orelse
            return ToolResult.fail("Missing 'url' parameter for read action");

        if (url.len > 0 and url[0] == '-') {
            return ToolResult.fail("Invalid URL for read action");
        }
        const uri = std.Uri.parse(url) catch
            return ToolResult.fail("Invalid URL format");
        if (!std.ascii.eqlIgnoreCase(uri.scheme, "https")) {
            return ToolResult.fail("Only https:// URLs are supported for security");
        }

        const fetched = fetchReadBody(allocator, url) catch |err| {
            if (err == error.LocalAddressBlocked) return ToolResult.fail("Blocked local/private host");
            if (err == error.HostSafetyCheckFailed) return ToolResult.fail("Unable to verify host safety");
            if (err == error.InvalidUrl) return ToolResult.fail("Invalid URL format");
            if (err == error.InsecureRedirect) return ToolResult.fail("Only https:// URLs are supported for security");
            const msg = try std.fmt.allocPrint(allocator, "HTTP read failed: {}", .{err});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };
        defer allocator.free(fetched);

        if (fetched.len == 0) {
            const msg = try allocator.dupe(u8, "Page returned empty response");
            return ToolResult{ .success = true, .output = msg };
        }

        // Truncate to MAX_READ_BYTES
        const truncated = fetched.len > MAX_READ_BYTES;
        const body_len = if (truncated) MAX_READ_BYTES else fetched.len;
        const suffix: []const u8 = if (truncated) "\n\n[Content truncated to 8 KB]" else "";

        const output = try std.fmt.allocPrint(allocator, "{s}{s}", .{ fetched[0..body_len], suffix });
        return ToolResult{ .success = true, .output = output };
    }
};

fn shouldUseResolvePin(host: []const u8) bool {
    return std.mem.indexOfScalar(u8, net_security.stripHostBrackets(host), ':') == null;
}

fn buildResolveEntry(
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
    connect_host: []const u8,
) ![]u8 {
    const host_for_resolve = net_security.stripHostBrackets(host);
    const connect_target = if (std.mem.indexOfScalar(u8, connect_host, ':') != null)
        try std.fmt.allocPrint(allocator, "[{s}]", .{connect_host})
    else
        try allocator.dupe(u8, connect_host);
    defer allocator.free(connect_target);

    return std.fmt.allocPrint(allocator, "{s}:{d}:{s}", .{ host_for_resolve, port, connect_target });
}

fn validateReadUrl(allocator: std.mem.Allocator, url: []const u8) !?[]u8 {
    const uri = std.Uri.parse(url) catch return error.InvalidUrl;
    if (!std.ascii.eqlIgnoreCase(uri.scheme, "https")) return error.InsecureRedirect;

    const host = net_security.extractHost(url) orelse return error.InvalidUrl;
    const resolved_port: u16 = uri.port orelse 443;

    if (builtin.is_test and http_util.hasTestNativeHttpHandler()) {
        return if (shouldUseResolvePin(host))
            try buildResolveEntry(allocator, host, resolved_port, host)
        else
            null;
    }

    const connect_host = net_security.resolveConnectHost(allocator, host, resolved_port) catch |err| switch (err) {
        error.LocalAddressBlocked => return error.LocalAddressBlocked,
        else => return error.HostSafetyCheckFailed,
    };
    defer allocator.free(connect_host);

    return if (shouldUseResolvePin(host))
        try buildResolveEntry(allocator, host, resolved_port, connect_host)
    else
        null;
}

fn headerValue(raw_headers: []const u8, name: []const u8) ?[]const u8 {
    var lines = std.mem.splitSequence(u8, raw_headers, "\r\n");
    _ = lines.next();
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const header_name = std.mem.trim(u8, line[0..colon], " \t");
        if (!std.ascii.eqlIgnoreCase(header_name, name)) continue;
        return std.mem.trim(u8, line[colon + 1 ..], " \t");
    }
    return null;
}

fn resolveRedirectUrl(allocator: std.mem.Allocator, base_url: []const u8, location: []const u8) ![]u8 {
    const trimmed = std.mem.trim(u8, location, " \t\r\n");
    if (trimmed.len == 0) return error.InvalidUrl;

    var aux_buf = try allocator.alloc(u8, trimmed.len + base_url.len + 32);
    defer allocator.free(aux_buf);
    @memcpy(aux_buf[0..trimmed.len], trimmed);

    var aux_slice = aux_buf[0..];
    const resolved = (try std.Uri.parse(base_url)).resolveInPlace(trimmed.len, &aux_slice) catch return error.InvalidUrl;
    if (!std.ascii.eqlIgnoreCase(resolved.scheme, "https")) return error.InsecureRedirect;

    return try std.fmt.allocPrint(allocator, "{f}", .{std.Uri.fmt(&resolved, .{
        .scheme = true,
        .authentication = true,
        .authority = true,
        .path = true,
        .query = true,
        .fragment = true,
        .port = true,
    })});
}

fn fetchReadBody(allocator: std.mem.Allocator, initial_url: []const u8) ![]u8 {
    var current_url = try allocator.dupe(u8, initial_url);
    defer allocator.free(current_url);

    var redirects: usize = 0;
    while (true) {
        const resolve_entry = try validateReadUrl(allocator, current_url);
        defer if (resolve_entry) |entry| allocator.free(entry);

        const response = try http_util.nativeHttpRequest(allocator, .{
            .method = .GET,
            .url = current_url,
            .timeout_secs = 10,
            .resolve_entry = resolve_entry,
            .max_response_bytes = MAX_FETCH_BYTES,
            .fail_on_http_error = false,
            .include_response_headers = true,
            .follow_redirects = false,
        });

        if (response.status_code >= 300 and response.status_code < 400) {
            const location = headerValue(response.headers, "location") orelse {
                response.deinit(allocator);
                return error.HttpRedirectLocationMissing;
            };
            if (redirects >= MAX_READ_REDIRECTS) {
                response.deinit(allocator);
                return error.TooManyHttpRedirects;
            }

            const next_url = resolveRedirectUrl(allocator, current_url, location) catch |err| {
                response.deinit(allocator);
                return err;
            };
            response.deinit(allocator);
            allocator.free(current_url);
            current_url = next_url;
            redirects += 1;
            continue;
        }

        allocator.free(response.headers);
        return response.body;
    }
}

// ── Tests ───────────────────────────────────────────────────────────

test "browser tool name" {
    var bt = BrowserTool{};
    const t = bt.tool();
    try std.testing.expectEqualStrings("browser", t.name());
}

test "browser open launches system browser" {
    var bt = BrowserTool{};
    const t = bt.tool();
    // In test mode, spawn is skipped; verify the output message is correct.
    const parsed = try root.parseTestArgs("{\"action\": \"open\", \"url\": \"https://example.com\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "example.com") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "stub") == null);
}

test "browser open rejects http" {
    var bt = BrowserTool{};
    const t = bt.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"open\", \"url\": \"http://example.com\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "https") != null);
}

test "browser screenshot redirects to screenshot tool" {
    var bt = BrowserTool{};
    const t = bt.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"screenshot\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "screenshot tool") != null);
}

// ── Additional browser tests ────────────────────────────────────

test "browser missing action parameter" {
    var bt = BrowserTool{};
    const t = bt.tool();
    const parsed = try root.parseTestArgs("{}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "action") != null);
}

test "browser open missing url" {
    var bt = BrowserTool{};
    const t = bt.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"open\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "url") != null);
}

test "browser click action requires CDP" {
    var bt = BrowserTool{};
    const t = bt.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"click\", \"selector\": \"#btn\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "CDP") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "click") != null);
}

test "browser read missing url" {
    var bt = BrowserTool{};
    const t = bt.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"read\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "url") != null);
}

test "browser read rejects http" {
    var bt = BrowserTool{};
    const t = bt.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"read\", \"url\": \"http://example.com\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "https") != null);
}

test "browser read rejects option-like url" {
    var bt = BrowserTool{};
    const t = bt.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"read\", \"url\": \"--help\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "Invalid") != null);
}

test "browser read blocks localhost SSRF" {
    var bt = BrowserTool{};
    const t = bt.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"read\", \"url\": \"https://127.0.0.1/\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expectEqualStrings("Blocked local/private host", result.error_msg.?);
}

test "browser read blocks loopback decimal alias SSRF" {
    var bt = BrowserTool{};
    const t = bt.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"read\", \"url\": \"https://2130706433/\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expectEqualStrings("Blocked local/private host", result.error_msg.?);
}

test "browser read native migration follows https redirect and truncates body" {
    const allocator = std.testing.allocator;
    const State = struct {
        var calls: usize = 0;

        fn handle(alloc: std.mem.Allocator, request: http_util.NativeHttpRequest) anyerror!http_util.NativeHttpResponse {
            calls += 1;
            try std.testing.expectEqual(std.http.Method.GET, request.method);
            try std.testing.expectEqual(@as(?u64, 10), request.timeout_secs);
            try std.testing.expectEqual(@as(usize, MAX_FETCH_BYTES), request.max_response_bytes);
            try std.testing.expect(request.include_response_headers);

            if (calls == 1) {
                try std.testing.expectEqualStrings("https://example.com/start", request.url);
                return .{
                    .status_code = 302,
                    .headers = try alloc.dupe(u8, "HTTP/1.1 302 Found\r\nLocation: /next"),
                    .body = try alloc.dupe(u8, ""),
                };
            }

            try std.testing.expectEqualStrings("https://example.com/next", request.url);
            const body = try alloc.alloc(u8, MAX_READ_BYTES + 4);
            @memset(body, 'a');
            return .{
                .status_code = 200,
                .headers = try alloc.dupe(u8, "HTTP/1.1 200 OK"),
                .body = body,
            };
        }
    };
    State.calls = 0;

    http_util.setTestNativeHttpHandler(State.handle);
    defer http_util.setTestNativeHttpHandler(null);

    var bt = BrowserTool{};
    const t = bt.tool();
    const parsed = try root.parseTestArgs("{\"action\":\"read\",\"url\":\"https://example.com/start\"}");
    defer parsed.deinit();

    const result = try t.execute(allocator, parsed.value.object);
    defer allocator.free(result.output);

    try std.testing.expect(result.success);
    try std.testing.expectEqual(@as(usize, 2), State.calls);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "[Content truncated to 8 KB]") != null);
}

test "browser read native migration rejects insecure redirect" {
    const allocator = std.testing.allocator;
    const handler = struct {
        fn handle(alloc: std.mem.Allocator, _: http_util.NativeHttpRequest) anyerror!http_util.NativeHttpResponse {
            return .{
                .status_code = 301,
                .headers = try alloc.dupe(u8, "HTTP/1.1 301 Moved\r\nLocation: http://example.com/plain"),
                .body = try alloc.dupe(u8, ""),
            };
        }
    }.handle;

    http_util.setTestNativeHttpHandler(handler);
    defer http_util.setTestNativeHttpHandler(null);

    var bt = BrowserTool{};
    const t = bt.tool();
    const parsed = try root.parseTestArgs("{\"action\":\"read\",\"url\":\"https://example.com/start\"}");
    defer parsed.deinit();

    const result = try t.execute(allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "https") != null);
}

test "browser open returns output with URL" {
    var bt = BrowserTool{};
    const t = bt.tool();
    // In test mode, spawn is skipped; verify the "Opened ..." message format.
    const parsed = try root.parseTestArgs("{\"action\": \"open\", \"url\": \"https://docs.example.com/api\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "docs.example.com") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "Opened") != null);
}

test "browser schema has enum values" {
    var bt = BrowserTool{};
    const t = bt.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "screenshot") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "open") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "click") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "scroll") != null);
}

test "browser description mentions browse" {
    var bt = BrowserTool{};
    const t = bt.tool();
    const desc = t.description();
    try std.testing.expect(std.mem.indexOf(u8, desc, "Browse") != null or std.mem.indexOf(u8, desc, "browse") != null or std.mem.indexOf(u8, desc, "web") != null);
}

test "browser tool schema has url" {
    var bt = BrowserTool{};
    const t = bt.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "url") != null);
}

test "browser tool schema has action" {
    var bt = BrowserTool{};
    const t = bt.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "action") != null);
}

test "browser tool execute with empty json" {
    var bt = BrowserTool{};
    const t = bt.tool();
    const parsed = try root.parseTestArgs("{}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
}

test "browser open rejects URL with shell metacharacters on Windows" {
    // On Windows, cmd.exe /c start interprets metacharacters — they must be blocked.
    // On Unix, open/xdg-open uses execvp so metacharacters in argv are safe.
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;

    var bt = BrowserTool{};
    const t = bt.tool();

    // & can chain commands in cmd.exe
    const p1 = try root.parseTestArgs("{\"action\": \"open\", \"url\": \"https://example.com&whoami\"}");
    defer p1.deinit();
    const r1 = try t.execute(std.testing.allocator, p1.value.object);
    try std.testing.expect(!r1.success);
    try std.testing.expect(std.mem.indexOf(u8, r1.error_msg.?, "metacharacter") != null);

    // | can pipe in cmd.exe
    const p2 = try root.parseTestArgs("{\"action\": \"open\", \"url\": \"https://example.com|calc\"}");
    defer p2.deinit();
    const r2 = try t.execute(std.testing.allocator, p2.value.object);
    try std.testing.expect(!r2.success);
}

test "browser open allows URL with query params on Unix" {
    // On Unix, & in query strings is safe (passed as argv to open/xdg-open).
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;

    var bt = BrowserTool{};
    const t = bt.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"open\", \"url\": \"https://example.com/search?a=1&b=2\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "example.com") != null);
}

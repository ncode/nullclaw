const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");
const config_types = @import("../config_types.zig");
const qr_mod = @import("../qr.zig");

const ILINK_BASE_URL = "https://ilinkai.weixin.qq.com/";
const ILINK_APP_ID = "bot";
const ILINK_CLIENT_VERSION = "131329"; // 2.1.1 encoded as 0x00020101
const CHANNEL_VERSION = "2.1.1";
const QR_POLL_INTERVAL_NS: u64 = 2 * std.time.ns_per_s;
const LOGIN_TIMEOUT_NS: u64 = 300 * std.time.ns_per_s;

pub const WeixinChannel = struct {
    allocator: std.mem.Allocator,
    config: config_types.WeixinConfig,
    running: bool = false,

    pub fn init(allocator: std.mem.Allocator, cfg: config_types.WeixinConfig) WeixinChannel {
        return .{ .allocator = allocator, .config = cfg };
    }

    pub fn initFromConfig(allocator: std.mem.Allocator, cfg: config_types.WeixinConfig) WeixinChannel {
        return init(allocator, cfg);
    }

    pub fn channelName(_: *WeixinChannel) []const u8 {
        return "weixin";
    }

    pub fn healthCheck(self: *WeixinChannel) bool {
        return self.running;
    }

    pub fn sendMessage(self: *WeixinChannel, target: []const u8, text: []const u8) !void {
        if (target.len == 0) return error.InvalidTarget;
        if (builtin.is_test) return;

        const token = self.config.token;
        if (token.len == 0) return error.WeixinMissingToken;

        var payload: std.ArrayListUnmanaged(u8) = .empty;
        defer payload.deinit(self.allocator);
        try appendSendMessagePayload(self.allocator, &payload, target, text);

        const url = try buildUrl(self.allocator, self.config.base_url, "ilink/bot/sendmessage");
        defer self.allocator.free(url);

        const headers = authHeaders(token);
        const resp = root.http_util.curlPostWithStatus(
            self.allocator,
            url,
            payload.items,
            &headers,
        ) catch return error.WeixinApiError;
        defer self.allocator.free(resp.body);
        if (resp.status_code < 200 or resp.status_code >= 300) return error.WeixinApiError;
    }

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        const self: *WeixinChannel = @ptrCast(@alignCast(ptr));
        self.running = true;
    }

    fn vtableStop(ptr: *anyopaque) void {
        const self: *WeixinChannel = @ptrCast(@alignCast(ptr));
        self.running = false;
    }

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8, _: []const []const u8) anyerror!void {
        const self: *WeixinChannel = @ptrCast(@alignCast(ptr));
        try self.sendMessage(target, message);
    }

    fn vtableName(ptr: *anyopaque) []const u8 {
        const self: *WeixinChannel = @ptrCast(@alignCast(ptr));
        return self.channelName();
    }

    fn vtableHealthCheck(ptr: *anyopaque) bool {
        const self: *WeixinChannel = @ptrCast(@alignCast(ptr));
        return self.healthCheck();
    }

    pub const vtable = root.Channel.VTable{
        .start = &vtableStart,
        .stop = &vtableStop,
        .send = &vtableSend,
        .name = &vtableName,
        .healthCheck = &vtableHealthCheck,
    };

    pub fn channel(self: *WeixinChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }
};

// ── iLink API types ────────────────────────────────────────────────

pub const QrCodeResponse = struct {
    qrcode: []const u8 = "",
    qrcode_img_content: []const u8 = "",
};

pub const StatusResponse = struct {
    status: []const u8 = "",
    bot_token: []const u8 = "",
    ilink_bot_id: []const u8 = "",
    baseurl: []const u8 = "",
    ilink_user_id: []const u8 = "",
    redirect_host: []const u8 = "",
};

pub const LoginResult = struct {
    bot_token: []u8,
    user_id: []u8,
    account_id: []u8,
    base_url: []u8,

    pub fn deinit(self: *LoginResult, allocator: std.mem.Allocator) void {
        allocator.free(self.bot_token);
        allocator.free(self.user_id);
        allocator.free(self.account_id);
        allocator.free(self.base_url);
    }
};

pub const LoginOptions = struct {
    base_url: []const u8 = ILINK_BASE_URL,
    timeout_ns: u64 = LOGIN_TIMEOUT_NS,
    proxy: ?[]const u8 = null,
};

// ── QR Login Flow ──────────────────────────────────────────────────

pub fn performLogin(allocator: std.mem.Allocator, opts: LoginOptions) !LoginResult {
    if (builtin.is_test) {
        return LoginResult{
            .bot_token = try allocator.dupe(u8, "test-bot-token"),
            .user_id = try allocator.dupe(u8, "test-user-id"),
            .account_id = try allocator.dupe(u8, "test-account-id"),
            .base_url = try allocator.dupe(u8, "https://test.example.com/"),
        };
    }

    const qr_resp = try requestQrCode(allocator, opts.base_url);
    defer allocator.free(qr_resp.qrcode);
    defer allocator.free(qr_resp.qrcode_img_content);

    // Display QR code in terminal
    try displayQrCode(qr_resp.qrcode_img_content);

    // Poll for scan status
    var poll_base_url: ?[]u8 = null;
    defer if (poll_base_url) |u| allocator.free(u);
    var scanned_printed = false;

    const deadline = std.time.nanoTimestamp() + @as(i128, opts.timeout_ns);

    while (std.time.nanoTimestamp() < deadline) {
        std.Thread.sleep(QR_POLL_INTERVAL_NS);

        const effective_base = if (poll_base_url) |u| u else opts.base_url;
        const status_resp = pollQrStatus(allocator, effective_base, qr_resp.qrcode) catch continue;
        defer {
            allocator.free(status_resp.status);
            allocator.free(status_resp.bot_token);
            allocator.free(status_resp.ilink_bot_id);
            allocator.free(status_resp.baseurl);
            allocator.free(status_resp.ilink_user_id);
            allocator.free(status_resp.redirect_host);
        }

        if (std.mem.eql(u8, status_resp.status, "wait")) {
            continue;
        } else if (std.mem.eql(u8, status_resp.status, "scaned")) {
            if (!scanned_printed) {
                std.debug.print("QR Code scanned! Please confirm login on your WeChat app...\n", .{});
                scanned_printed = true;
            }
        } else if (std.mem.eql(u8, status_resp.status, "confirmed")) {
            if (status_resp.bot_token.len == 0 or status_resp.ilink_bot_id.len == 0) {
                return error.WeixinLoginMissingCredentials;
            }
            const result_base = if (status_resp.baseurl.len > 0)
                try allocator.dupe(u8, status_resp.baseurl)
            else
                try allocator.dupe(u8, opts.base_url);
            errdefer allocator.free(result_base);

            return LoginResult{
                .bot_token = try allocator.dupe(u8, status_resp.bot_token),
                .user_id = try allocator.dupe(u8, status_resp.ilink_user_id),
                .account_id = try allocator.dupe(u8, status_resp.ilink_bot_id),
                .base_url = result_base,
            };
        } else if (std.mem.eql(u8, status_resp.status, "scaned_but_redirect")) {
            if (status_resp.redirect_host.len > 0) {
                const new_url = try std.fmt.allocPrint(allocator, "https://{s}/", .{status_resp.redirect_host});
                if (poll_base_url) |old| allocator.free(old);
                poll_base_url = new_url;
                std.debug.print("Switched polling host to {s}\n", .{status_resp.redirect_host});
            }
        } else if (std.mem.eql(u8, status_resp.status, "expired")) {
            return error.WeixinQrCodeExpired;
        }
    }

    return error.WeixinLoginTimeout;
}

fn displayQrCode(url: []const u8) !void {
    std.debug.print("\n=======================================================\n", .{});
    std.debug.print("Please scan the following QR code with WeChat to login:\n", .{});
    std.debug.print("=======================================================\n\n", .{});

    const qr = qr_mod.encode(url) catch {
        std.debug.print("(Could not generate QR code in terminal)\n", .{});
        std.debug.print("QR Code Link: {s}\n\n", .{url});
        return;
    };

    var buf: [8192]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    qr_mod.renderTerminal(&qr, fbs.writer()) catch {
        std.debug.print("(Could not render QR code)\n", .{});
        std.debug.print("QR Code Link: {s}\n\n", .{url});
        return;
    };

    std.debug.print("{s}", .{fbs.getWritten()});
    std.debug.print("\nQR Code Link: {s}\n\n", .{url});
    std.debug.print("Waiting for scan...\n", .{});
}

// ── iLink API Client ───────────────────────────────────────────────

fn ilinkHeaders() [2][]const u8 {
    return .{
        "iLink-App-Id: " ++ ILINK_APP_ID,
        "iLink-App-ClientVersion: " ++ ILINK_CLIENT_VERSION,
    };
}

fn authHeaders(token: []const u8) [5][]const u8 {
    _ = token;
    return .{
        "iLink-App-Id: " ++ ILINK_APP_ID,
        "iLink-App-ClientVersion: " ++ ILINK_CLIENT_VERSION,
        "AuthorizationType: ilink_bot_token",
        "Content-Type: application/json",
        "X-WECHAT-UIN: MTIzNDU2Nzg5MA==",
    };
}

fn buildUrl(allocator: std.mem.Allocator, base_url: []const u8, endpoint: []const u8) ![]u8 {
    const base = std.mem.trimRight(u8, base_url, "/");
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ base, endpoint });
}

fn requestQrCode(allocator: std.mem.Allocator, base_url: []const u8) !struct { qrcode: []u8, qrcode_img_content: []u8 } {
    const url = try std.fmt.allocPrint(allocator, "{s}ilink/bot/get_bot_qrcode?bot_type=3", .{
        if (std.mem.endsWith(u8, base_url, "/")) base_url else blk: {
            // base_url always ends with / from default
            break :blk base_url;
        },
    });
    defer allocator.free(url);

    const headers = ilinkHeaders();
    const resp_body = root.http_util.curlGet(allocator, url, &headers, "15") catch return error.WeixinApiError;
    defer allocator.free(resp_body);

    var parsed = std.json.parseFromSlice(std.json.Value, allocator, resp_body, .{}) catch return error.WeixinApiError;
    defer parsed.deinit();

    if (parsed.value != .object) return error.WeixinApiError;

    const qrcode_val = parsed.value.object.get("qrcode") orelse return error.WeixinApiError;
    const img_val = parsed.value.object.get("qrcode_img_content") orelse return error.WeixinApiError;

    if (qrcode_val != .string or img_val != .string) return error.WeixinApiError;
    if (qrcode_val.string.len == 0) return error.WeixinApiError;

    return .{
        .qrcode = try allocator.dupe(u8, qrcode_val.string),
        .qrcode_img_content = try allocator.dupe(u8, img_val.string),
    };
}

fn pollQrStatus(allocator: std.mem.Allocator, base_url: []const u8, qrcode: []const u8) !StatusResponse {
    const base = if (std.mem.endsWith(u8, base_url, "/")) base_url else base_url;
    const url = try std.fmt.allocPrint(allocator, "{s}ilink/bot/get_qrcode_status?qrcode={s}", .{ base, qrcode });
    defer allocator.free(url);

    const headers = ilinkHeaders();
    const resp_body = root.http_util.curlGet(allocator, url, &headers, "30") catch return error.WeixinApiError;
    defer allocator.free(resp_body);

    return parseStatusResponse(allocator, resp_body);
}

pub fn parseStatusResponse(allocator: std.mem.Allocator, json_body: []const u8) !StatusResponse {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, json_body, .{}) catch return error.WeixinApiError;
    defer parsed.deinit();

    if (parsed.value != .object) return error.WeixinApiError;
    const obj = parsed.value.object;

    const status = obj.get("status") orelse return error.WeixinApiError;
    if (status != .string) return error.WeixinApiError;

    return StatusResponse{
        .status = try allocator.dupe(u8, status.string),
        .bot_token = try dupeOptionalString(allocator, obj, "bot_token"),
        .ilink_bot_id = try dupeOptionalString(allocator, obj, "ilink_bot_id"),
        .baseurl = try dupeOptionalString(allocator, obj, "baseurl"),
        .ilink_user_id = try dupeOptionalString(allocator, obj, "ilink_user_id"),
        .redirect_host = try dupeOptionalString(allocator, obj, "redirect_host"),
    };
}

fn dupeOptionalString(allocator: std.mem.Allocator, obj: std.json.ObjectMap, key: []const u8) ![]u8 {
    const val = obj.get(key) orelse return try allocator.dupe(u8, "");
    if (val != .string) return try allocator.dupe(u8, "");
    return try allocator.dupe(u8, val.string);
}

fn appendSendMessagePayload(allocator: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8), to_user: []const u8, text: []const u8) !void {
    const w = out.writer(allocator);
    try w.writeAll("{\"base_info\":{\"channel_version\":\"" ++ CHANNEL_VERSION ++ "\"},\"to_user\":");
    try root.appendJsonStringW(w, to_user);
    try w.writeAll(",\"content_type\":\"text\",\"content\":{\"text\":");
    try root.appendJsonStringW(w, text);
    try w.writeAll("}}");
}

// ── Tests ──────────────────────────────────────────────────────────

test "weixin channel vtable contract" {
    var ch = WeixinChannel.init(std.testing.allocator, .{});
    try std.testing.expectEqualStrings("weixin", ch.channel().name());
    try std.testing.expect(!ch.channel().healthCheck());

    try ch.channel().start();
    try std.testing.expect(ch.channel().healthCheck());

    ch.channel().stop();
    try std.testing.expect(!ch.channel().healthCheck());
}

test "parseStatusResponse parses wait status" {
    const json =
        \\{"status":"wait"}
    ;
    const resp = try parseStatusResponse(std.testing.allocator, json);
    defer {
        std.testing.allocator.free(resp.status);
        std.testing.allocator.free(resp.bot_token);
        std.testing.allocator.free(resp.ilink_bot_id);
        std.testing.allocator.free(resp.baseurl);
        std.testing.allocator.free(resp.ilink_user_id);
        std.testing.allocator.free(resp.redirect_host);
    }
    try std.testing.expectEqualStrings("wait", resp.status);
}

test "parseStatusResponse parses confirmed status with credentials" {
    const json =
        \\{"status":"confirmed","bot_token":"tk_abc123","ilink_bot_id":"bot_456","ilink_user_id":"user_789","baseurl":"https://region.example.com/"}
    ;
    const resp = try parseStatusResponse(std.testing.allocator, json);
    defer {
        std.testing.allocator.free(resp.status);
        std.testing.allocator.free(resp.bot_token);
        std.testing.allocator.free(resp.ilink_bot_id);
        std.testing.allocator.free(resp.baseurl);
        std.testing.allocator.free(resp.ilink_user_id);
        std.testing.allocator.free(resp.redirect_host);
    }
    try std.testing.expectEqualStrings("confirmed", resp.status);
    try std.testing.expectEqualStrings("tk_abc123", resp.bot_token);
    try std.testing.expectEqualStrings("bot_456", resp.ilink_bot_id);
    try std.testing.expectEqualStrings("user_789", resp.ilink_user_id);
    try std.testing.expectEqualStrings("https://region.example.com/", resp.baseurl);
}

test "parseStatusResponse parses scaned_but_redirect" {
    const json =
        \\{"status":"scaned_but_redirect","redirect_host":"region2.weixin.qq.com"}
    ;
    const resp = try parseStatusResponse(std.testing.allocator, json);
    defer {
        std.testing.allocator.free(resp.status);
        std.testing.allocator.free(resp.bot_token);
        std.testing.allocator.free(resp.ilink_bot_id);
        std.testing.allocator.free(resp.baseurl);
        std.testing.allocator.free(resp.ilink_user_id);
        std.testing.allocator.free(resp.redirect_host);
    }
    try std.testing.expectEqualStrings("scaned_but_redirect", resp.status);
    try std.testing.expectEqualStrings("region2.weixin.qq.com", resp.redirect_host);
}

test "parseStatusResponse rejects invalid JSON" {
    try std.testing.expectError(error.WeixinApiError, parseStatusResponse(std.testing.allocator, "not json"));
}

test "parseStatusResponse rejects missing status field" {
    try std.testing.expectError(error.WeixinApiError, parseStatusResponse(std.testing.allocator, "{}"));
}

test "appendSendMessagePayload builds correct JSON" {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    try appendSendMessagePayload(std.testing.allocator, &buf, "user123", "hello");
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"to_user\":\"user123\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"text\":\"hello\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, CHANNEL_VERSION) != null);
}

test "buildUrl joins base and endpoint" {
    const url = try buildUrl(std.testing.allocator, "https://example.com/", "ilink/bot/test");
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings("https://example.com/ilink/bot/test", url);
}

test "buildUrl handles base without trailing slash" {
    const url = try buildUrl(std.testing.allocator, "https://example.com", "ilink/bot/test");
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings("https://example.com/ilink/bot/test", url);
}

test "performLogin returns test data in test mode" {
    var result = try performLogin(std.testing.allocator, .{});
    defer result.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("test-bot-token", result.bot_token);
    try std.testing.expectEqualStrings("test-account-id", result.account_id);
}

test "sendMessage returns in test mode" {
    var ch = WeixinChannel.init(std.testing.allocator, .{ .token = "test-token" });
    try ch.sendMessage("target", "hello");
}

test "sendMessage rejects empty target" {
    var ch = WeixinChannel.init(std.testing.allocator, .{ .token = "test-token" });
    try std.testing.expectError(error.InvalidTarget, ch.sendMessage("", "hello"));
}

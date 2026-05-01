const std = @import("std");
const std_compat = @import("compat");
const root = @import("root.zig");

pub const SentMessageMeta = struct {
    message_id: ?i64 = null,
};

pub const ForumTopicMeta = struct {
    message_thread_id: i64,
};

pub const BotIdentity = struct {
    user_id: ?i64 = null,
    username: ?[]u8 = null,

    pub fn deinit(self: *const BotIdentity, allocator: std.mem.Allocator) void {
        if (self.username) |name| allocator.free(name);
    }
};

pub const Client = struct {
    allocator: std.mem.Allocator,
    bot_token: []const u8,
    proxy: ?[]const u8,

    pub fn apiUrl(self: Client, buf: []u8, method: []const u8) ![]const u8 {
        var w: std.Io.Writer = .fixed(buf);
        try w.print("https://api.telegram.org/bot{s}/{s}", .{ self.bot_token, method });
        return w.buffered();
    }

    pub fn getMe(self: Client, allocator: std.mem.Allocator) ![]u8 {
        return self.post(allocator, "getMe", "{}", "10");
    }

    pub fn getMeOk(self: Client) bool {
        const resp = self.getMe(self.allocator) catch return false;
        defer self.allocator.free(resp);
        return std.mem.indexOf(u8, resp, "\"ok\":true") != null;
    }

    pub fn fetchBotIdentity(self: Client, allocator: std.mem.Allocator) ?BotIdentity {
        const resp = self.getMe(allocator) catch return null;
        defer allocator.free(resp);
        return parseBotIdentity(allocator, resp);
    }

    pub fn setMyCommands(self: Client, commands_json: []const u8) !void {
        const resp = try self.post(self.allocator, "setMyCommands", commands_json, "10");
        defer self.allocator.free(resp);
        if (responseHasTelegramError(resp)) return error.TelegramApiError;
    }

    pub fn deleteMyCommands(self: Client, body_json: []const u8) !void {
        const resp = try self.post(self.allocator, "deleteMyCommands", body_json, "10");
        defer self.allocator.free(resp);
        if (responseHasTelegramError(resp)) return error.TelegramApiError;
    }

    pub fn deleteWebhookKeepPending(self: Client) !void {
        const resp = try self.post(self.allocator, "deleteWebhook", "{\"drop_pending_updates\":false}", "10");
        self.allocator.free(resp);
    }

    pub fn latestUpdateNextOffset(self: Client, allocator: std.mem.Allocator) ?i64 {
        const resp = self.post(allocator, "getUpdates", "{\"offset\":-1,\"timeout\":0}", "10") catch return null;
        defer allocator.free(resp);

        const parsed = std.json.parseFromSlice(std.json.Value, allocator, resp, .{}) catch return null;
        defer parsed.deinit();
        if (parsed.value != .object) return null;

        const result_val = parsed.value.object.get("result") orelse return null;
        if (result_val != .array) return null;

        var next_offset: ?i64 = null;
        for (result_val.array.items) |update| {
            if (update != .object) continue;
            const uid = update.object.get("update_id") orelse continue;
            if (uid != .integer) continue;
            next_offset = uid.integer + 1;
        }
        return next_offset;
    }

    pub fn sendTypingIndicator(self: Client, chat_id: []const u8, message_thread_id: ?i64) !void {
        var body: std.ArrayListUnmanaged(u8) = .empty;
        defer body.deinit(self.allocator);

        try body.appendSlice(self.allocator, "{\"chat_id\":");
        try body.appendSlice(self.allocator, chat_id);
        try appendMessageThreadId(&body, self.allocator, message_thread_id);
        try body.appendSlice(self.allocator, ",\"action\":\"typing\"}");

        const resp = try self.post(self.allocator, "sendChatAction", body.items, "10");
        self.allocator.free(resp);
    }

    pub fn answerCallbackQuery(self: Client, callback_query_id: []const u8, text: ?[]const u8) !void {
        var body: std.ArrayListUnmanaged(u8) = .empty;
        defer body.deinit(self.allocator);

        try body.appendSlice(self.allocator, "{\"callback_query_id\":");
        try root.json_util.appendJsonString(&body, self.allocator, callback_query_id);
        if (text) |t| {
            try body.appendSlice(self.allocator, ",\"text\":");
            try root.json_util.appendJsonString(&body, self.allocator, t);
        }
        try body.appendSlice(self.allocator, "}");

        const resp = try self.post(self.allocator, "answerCallbackQuery", body.items, "10");
        self.allocator.free(resp);
    }

    pub fn clearReplyMarkup(self: Client, chat_id: []const u8, message_id: i64) !void {
        var body: std.ArrayListUnmanaged(u8) = .empty;
        defer body.deinit(self.allocator);

        try body.appendSlice(self.allocator, "{\"chat_id\":");
        try body.appendSlice(self.allocator, chat_id);

        var msg_id_buf: [32]u8 = undefined;
        const msg_id_str = try std.fmt.bufPrint(&msg_id_buf, "{d}", .{message_id});
        try body.appendSlice(self.allocator, ",\"message_id\":");
        try body.appendSlice(self.allocator, msg_id_str);
        try body.appendSlice(self.allocator, ",\"reply_markup\":{\"inline_keyboard\":[]}}");

        const resp = try self.post(self.allocator, "editMessageReplyMarkup", body.items, "10");
        self.allocator.free(resp);
    }

    pub fn editMessageText(self: Client, allocator: std.mem.Allocator, chat_id: []const u8, message_id: i64, text: []const u8, reply_markup_json: ?[]const u8) ![]u8 {
        const body = try buildEditMessageTextBody(allocator, chat_id, message_id, text, reply_markup_json, null);
        defer allocator.free(body);
        return self.post(allocator, "editMessageText", body, "30");
    }

    pub fn editMessageTextHtml(self: Client, allocator: std.mem.Allocator, chat_id: []const u8, message_id: i64, text: []const u8, reply_markup_json: ?[]const u8) ![]u8 {
        const body = try buildEditMessageTextBody(allocator, chat_id, message_id, text, reply_markup_json, "HTML");
        defer allocator.free(body);
        return self.post(allocator, "editMessageText", body, "30");
    }

    fn buildEditMessageTextBody(
        allocator: std.mem.Allocator,
        chat_id: []const u8,
        message_id: i64,
        text: []const u8,
        reply_markup_json: ?[]const u8,
        parse_mode: ?[]const u8,
    ) ![]u8 {
        var body: std.ArrayListUnmanaged(u8) = .empty;
        errdefer body.deinit(allocator);

        try body.appendSlice(allocator, "{\"chat_id\":");
        try body.appendSlice(allocator, chat_id);

        var msg_id_buf: [32]u8 = undefined;
        const msg_id_str = try std.fmt.bufPrint(&msg_id_buf, "{d}", .{message_id});
        try body.appendSlice(allocator, ",\"message_id\":");
        try body.appendSlice(allocator, msg_id_str);
        try body.appendSlice(allocator, ",\"text\":");
        try root.json_util.appendJsonString(&body, allocator, text);
        if (parse_mode) |mode| {
            try body.appendSlice(allocator, ",\"parse_mode\":");
            try root.json_util.appendJsonString(&body, allocator, mode);
        }
        try appendRawReplyMarkup(&body, allocator, reply_markup_json);
        try body.appendSlice(allocator, "}");

        return body.toOwnedSlice(allocator);
    }

    pub fn setMessageReaction(self: Client, chat_id: []const u8, message_id: i64, emoji: ?[]const u8) !void {
        var body: std.ArrayListUnmanaged(u8) = .empty;
        defer body.deinit(self.allocator);

        try body.appendSlice(self.allocator, "{\"chat_id\":");
        try body.appendSlice(self.allocator, chat_id);

        var msg_id_buf: [32]u8 = undefined;
        const msg_id_str = try std.fmt.bufPrint(&msg_id_buf, "{d}", .{message_id});
        try body.appendSlice(self.allocator, ",\"message_id\":");
        try body.appendSlice(self.allocator, msg_id_str);
        try body.appendSlice(self.allocator, ",\"reaction\":");
        if (emoji) |value| {
            try body.appendSlice(self.allocator, "[{\"type\":\"emoji\",\"emoji\":");
            try root.json_util.appendJsonString(&body, self.allocator, value);
            try body.appendSlice(self.allocator, "}]");
        } else {
            try body.appendSlice(self.allocator, "[]");
        }
        try body.appendSlice(self.allocator, ",\"is_big\":false}");

        const resp = try self.post(self.allocator, "setMessageReaction", body.items, "10");
        defer self.allocator.free(resp);
        if (responseHasTelegramError(resp)) return error.TelegramApiError;
    }

    pub fn createForumTopic(self: Client, allocator: std.mem.Allocator, chat_id: []const u8, name: []const u8) !ForumTopicMeta {
        var body: std.ArrayListUnmanaged(u8) = .empty;
        defer body.deinit(allocator);

        try body.appendSlice(allocator, "{\"chat_id\":");
        try body.appendSlice(allocator, chat_id);
        try body.appendSlice(allocator, ",\"name\":");
        try root.json_util.appendJsonString(&body, allocator, name);
        try body.appendSlice(allocator, "}");

        const resp = try self.post(allocator, "createForumTopic", body.items, "30");
        defer allocator.free(resp);
        if (responseHasTelegramError(resp)) return error.TelegramApiError;
        return parseForumTopicMeta(allocator, resp) orelse error.InvalidResponse;
    }

    pub fn sendMessage(self: Client, allocator: std.mem.Allocator, body: []const u8, timeout: []const u8) ![]u8 {
        return self.post(allocator, "sendMessage", body, timeout);
    }

    pub fn getUpdates(self: Client, allocator: std.mem.Allocator, body: []const u8, timeout: []const u8) ![]u8 {
        return self.post(allocator, "getUpdates", body, timeout);
    }

    pub fn sendMessageDraft(self: Client, allocator: std.mem.Allocator, body: []const u8) ![]u8 {
        return self.post(allocator, "sendMessageDraft", body, "10");
    }

    pub fn getFilePath(self: Client, allocator: std.mem.Allocator, file_id: []const u8) ![]u8 {
        var body: std.ArrayListUnmanaged(u8) = .empty;
        defer body.deinit(allocator);
        try body.appendSlice(allocator, "{\"file_id\":");
        try root.json_util.appendJsonString(&body, allocator, file_id);
        try body.appendSlice(allocator, "}");

        const resp = try self.post(allocator, "getFile", body.items, "15");
        defer allocator.free(resp);

        const parsed = std.json.parseFromSlice(std.json.Value, allocator, resp, .{}) catch |err| {
            return switch (err) {
                else => error.InvalidResponse,
            };
        };
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidResponse;

        const result_obj = parsed.value.object.get("result") orelse return error.InvalidResponse;
        if (result_obj != .object) return error.InvalidResponse;

        const fp_val = result_obj.object.get("file_path") orelse return error.InvalidResponse;
        if (fp_val != .string) return error.InvalidResponse;

        return allocator.dupe(u8, fp_val.string);
    }

    pub fn downloadFile(self: Client, allocator: std.mem.Allocator, file_path: []const u8, timeout: []const u8) ![]u8 {
        var url_buf: [1024]u8 = undefined;
        const url = try self.fileUrl(&url_buf, file_path);
        return root.http_util.httpGetWithProxy(allocator, url, &.{}, timeout, self.proxy);
    }

    pub fn postMultipart(
        self: Client,
        allocator: std.mem.Allocator,
        method: []const u8,
        chat_id: []const u8,
        message_thread_id: ?i64,
        field_name: []const u8,
        media_path: []const u8,
        caption: ?[]const u8,
    ) !void {
        var url_buf: [512]u8 = undefined;
        const url = try self.apiUrl(&url_buf, method);

        const boundary = "nullclaw-telegram-upload-boundary";
        var body: std.ArrayListUnmanaged(u8) = .empty;
        defer body.deinit(allocator);

        try appendMultipartField(&body, allocator, boundary, "chat_id", chat_id);
        if (message_thread_id) |thread_id| {
            var thread_buf: [32]u8 = undefined;
            const thread_value = try std.fmt.bufPrint(&thread_buf, "{d}", .{thread_id});
            try appendMultipartField(&body, allocator, boundary, "message_thread_id", thread_value);
        }

        if (std.mem.startsWith(u8, media_path, "http://") or
            std.mem.startsWith(u8, media_path, "https://"))
        {
            try appendMultipartField(&body, allocator, boundary, field_name, media_path);
        } else {
            const media_file = std_compat.fs.openFileAbsolute(media_path, .{}) catch return error.HttpReadError;
            defer media_file.close();
            const media_data = media_file.readToEndAlloc(allocator, 64 * 1024 * 1024) catch return error.HttpReadError;
            defer allocator.free(media_data);
            try appendMultipartFile(&body, allocator, boundary, field_name, "media", media_data);
        }

        if (caption) |cap| {
            try appendMultipartField(&body, allocator, boundary, "caption", cap);
        }
        try body.appendSlice(allocator, "--" ++ boundary ++ "--\r\n");

        const content_type = "Content-Type: multipart/form-data; boundary=" ++ boundary;
        const response = try root.http_util.nativeHttpRequest(allocator, .{
            .method = .POST,
            .url = url,
            .payload = body.items,
            .headers = &.{.{ .name = "Content-Type", .value = content_type }},
            .proxy = self.proxy,
            .timeout_secs = 120,
            .max_response_bytes = 1024 * 1024,
            .fail_on_http_error = false,
        });
        response.deinit(allocator);
    }

    fn post(self: Client, allocator: std.mem.Allocator, method: []const u8, body: []const u8, timeout: []const u8) ![]u8 {
        var url_buf: [512]u8 = undefined;
        const url = try self.apiUrl(&url_buf, method);
        return root.http_util.httpPostWithProxy(allocator, url, body, &.{}, self.proxy, timeout);
    }

    fn fileUrl(self: Client, buf: []u8, file_path: []const u8) ![]const u8 {
        var w: std.Io.Writer = .fixed(buf);
        try w.print("https://api.telegram.org/file/bot{s}/{s}", .{ self.bot_token, file_path });
        return w.buffered();
    }
};

pub fn appendReplyTo(body: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, reply_to: ?i64) !void {
    if (reply_to) |rid| {
        var rid_buf: [32]u8 = undefined;
        const rid_str = std.fmt.bufPrint(&rid_buf, "{d}", .{rid}) catch unreachable;
        try body.appendSlice(allocator, ",\"reply_parameters\":{\"message_id\":");
        try body.appendSlice(allocator, rid_str);
        try body.appendSlice(allocator, "}");
    }
}

pub fn appendMessageThreadId(body: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, message_thread_id: ?i64) !void {
    if (message_thread_id) |thread_id| {
        var thread_buf: [32]u8 = undefined;
        const thread_str = std.fmt.bufPrint(&thread_buf, "{d}", .{thread_id}) catch unreachable;
        try body.appendSlice(allocator, ",\"message_thread_id\":");
        try body.appendSlice(allocator, thread_str);
    }
}

pub fn appendRawReplyMarkup(body: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, reply_markup_json: ?[]const u8) !void {
    if (reply_markup_json) |rm| {
        try body.appendSlice(allocator, ",\"reply_markup\":");
        try body.appendSlice(allocator, rm);
    }
}

fn appendMultipartField(
    body: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    boundary: []const u8,
    name: []const u8,
    value: []const u8,
) !void {
    try body.appendSlice(allocator, "--");
    try body.appendSlice(allocator, boundary);
    try body.appendSlice(allocator, "\r\nContent-Disposition: form-data; name=\"");
    try body.appendSlice(allocator, name);
    try body.appendSlice(allocator, "\"\r\n\r\n");
    try body.appendSlice(allocator, value);
    try body.appendSlice(allocator, "\r\n");
}

fn appendMultipartFile(
    body: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    boundary: []const u8,
    name: []const u8,
    filename: []const u8,
    file_data: []const u8,
) !void {
    try body.appendSlice(allocator, "--");
    try body.appendSlice(allocator, boundary);
    try body.appendSlice(allocator, "\r\nContent-Disposition: form-data; name=\"");
    try body.appendSlice(allocator, name);
    try body.appendSlice(allocator, "\"; filename=\"");
    try body.appendSlice(allocator, filename);
    try body.appendSlice(allocator, "\"\r\nContent-Type: application/octet-stream\r\n\r\n");
    try body.appendSlice(allocator, file_data);
    try body.appendSlice(allocator, "\r\n");
}

pub fn responseHasTelegramError(resp: []const u8) bool {
    return std.mem.indexOf(u8, resp, "\"error_code\"") != null or
        std.mem.indexOf(u8, resp, "\"ok\":false") != null;
}

pub fn responseIsMessageTooLong(resp: []const u8) bool {
    return std.mem.indexOf(u8, resp, "MESSAGE_TOO_LONG") != null or
        std.mem.indexOf(u8, resp, "message is too long") != null;
}

pub fn responseIsDraftPeerInvalid(resp: []const u8) bool {
    return std.mem.indexOf(u8, resp, "TEXTDRAFT_PEER_INVALID") != null;
}

pub fn parseRetryAfterSecs(allocator: std.mem.Allocator, resp: []const u8) ?u32 {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, resp, .{}) catch return null;
    defer parsed.deinit();
    if (parsed.value != .object) return null;

    const parameters_val = parsed.value.object.get("parameters") orelse return null;
    if (parameters_val != .object) return null;

    const retry_after_val = parameters_val.object.get("retry_after") orelse return null;
    return switch (retry_after_val) {
        .integer => |value| if (value >= 0) @as(u32, @intCast(value)) else null,
        else => null,
    };
}

pub fn parseSentMessageMeta(allocator: std.mem.Allocator, resp: []const u8) ?SentMessageMeta {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, resp, .{}) catch return null;
    defer parsed.deinit();
    if (parsed.value != .object) return null;

    const ok_val = parsed.value.object.get("ok") orelse return null;
    if (ok_val != .bool or !ok_val.bool) return null;

    const result_val = parsed.value.object.get("result") orelse return null;
    if (result_val != .object) return null;

    const msg_id_val = result_val.object.get("message_id") orelse return .{};
    if (msg_id_val != .integer) return .{};
    return .{ .message_id = msg_id_val.integer };
}

pub fn parseForumTopicMeta(allocator: std.mem.Allocator, resp: []const u8) ?ForumTopicMeta {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, resp, .{}) catch return null;
    defer parsed.deinit();
    if (parsed.value != .object) return null;

    const ok_val = parsed.value.object.get("ok") orelse return null;
    if (ok_val != .bool or !ok_val.bool) return null;

    const result_val = parsed.value.object.get("result") orelse return null;
    if (result_val != .object) return null;

    const thread_id_val = result_val.object.get("message_thread_id") orelse return null;
    if (thread_id_val != .integer or thread_id_val.integer <= 0) return null;

    return .{ .message_thread_id = thread_id_val.integer };
}

fn parseBotIdentity(allocator: std.mem.Allocator, resp: []const u8) ?BotIdentity {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, resp, .{}) catch return null;
    defer parsed.deinit();
    if (parsed.value != .object) return null;

    const result_val = parsed.value.object.get("result") orelse return null;
    if (result_val != .object) return null;

    const id_val = result_val.object.get("id");
    const username_val = result_val.object.get("username");

    return .{
        .user_id = if (id_val) |value| (if (value == .integer) value.integer else null) else null,
        .username = if (username_val) |value|
            (if (value == .string) (allocator.dupe(u8, value.string) catch null) else null)
        else
            null,
    };
}

test "telegram api client builds method url" {
    const client = Client{
        .allocator = std.testing.allocator,
        .bot_token = "123:ABC",
        .proxy = null,
    };
    var buf: [256]u8 = undefined;
    const url = try client.apiUrl(&buf, "getUpdates");
    try std.testing.expectEqualStrings("https://api.telegram.org/bot123:ABC/getUpdates", url);
}

test "telegram api postMultipart native migration sends file form fields" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    {
        var media = try std_compat.fs.Dir.wrap(tmp_dir.dir).createFile("photo.jpg", .{});
        defer media.close();
        try media.writeAll("jpeg-bytes");
    }
    const media_path = try std_compat.fs.Dir.wrap(tmp_dir.dir).realpathAlloc(allocator, "photo.jpg");
    defer allocator.free(media_path);

    const handler = struct {
        fn handle(alloc: std.mem.Allocator, request: root.http_util.NativeHttpRequest) anyerror!root.http_util.NativeHttpResponse {
            try std.testing.expectEqual(std.http.Method.POST, request.method);
            try std.testing.expectEqualStrings("https://api.telegram.org/bot123:ABC/sendPhoto", request.url);
            try std.testing.expectEqualStrings("socks5://127.0.0.1:1080", request.proxy.?);
            try std.testing.expectEqual(@as(?u64, 120), request.timeout_secs);
            try std.testing.expect(request.payload != null);
            try std.testing.expect(std.mem.indexOf(u8, request.payload.?, "name=\"chat_id\"") != null);
            try std.testing.expect(std.mem.indexOf(u8, request.payload.?, "chat_1") != null);
            try std.testing.expect(std.mem.indexOf(u8, request.payload.?, "name=\"message_thread_id\"") != null);
            try std.testing.expect(std.mem.indexOf(u8, request.payload.?, "name=\"photo\"; filename=\"media\"") != null);
            try std.testing.expect(std.mem.indexOf(u8, request.payload.?, "jpeg-bytes") != null);
            try std.testing.expect(std.mem.indexOf(u8, request.payload.?, "name=\"caption\"") != null);
            return .{ .status_code = 200, .body = try alloc.dupe(u8, "{\"ok\":true}") };
        }
    }.handle;

    root.http_util.setTestNativeHttpHandler(handler);
    defer root.http_util.setTestNativeHttpHandler(null);

    const client = Client{
        .allocator = allocator,
        .bot_token = "123:ABC",
        .proxy = "socks5://127.0.0.1:1080",
    };
    try client.postMultipart(allocator, "sendPhoto", "chat_1", 9, "photo", media_path, "caption text");
}

test "telegram api responseHasTelegramError matches error payloads" {
    try std.testing.expect(responseHasTelegramError("{\"ok\":false,\"error_code\":400}"));
    try std.testing.expect(!responseHasTelegramError("{\"ok\":true,\"result\":{}}"));
}

test "telegram api responseIsMessageTooLong matches telegram payloads" {
    try std.testing.expect(responseIsMessageTooLong(
        "{\"ok\":false,\"error_code\":400,\"description\":\"Bad Request: MESSAGE_TOO_LONG\"}",
    ));
    try std.testing.expect(!responseIsMessageTooLong(
        "{\"ok\":false,\"error_code\":429,\"description\":\"Too Many Requests\"}",
    ));
}

test "telegram api responseIsDraftPeerInvalid matches telegram payloads" {
    try std.testing.expect(responseIsDraftPeerInvalid(
        "{\"ok\":false,\"error_code\":400,\"description\":\"Bad Request: TEXTDRAFT_PEER_INVALID\"}",
    ));
    try std.testing.expect(!responseIsDraftPeerInvalid(
        "{\"ok\":false,\"error_code\":400,\"description\":\"Bad Request: MESSAGE_TOO_LONG\"}",
    ));
}

test "telegram api parseRetryAfterSecs extracts retry_after" {
    const retry_after = parseRetryAfterSecs(
        std.testing.allocator,
        "{\"ok\":false,\"error_code\":429,\"parameters\":{\"retry_after\":12}}",
    ) orelse return error.TestExpectedEqual;
    try std.testing.expectEqual(@as(u32, 12), retry_after);
}

test "telegram api parseSentMessageMeta extracts message id" {
    const meta = parseSentMessageMeta(
        std.testing.allocator,
        "{\"ok\":true,\"result\":{\"message_id\":42}}",
    ) orelse return error.TestExpectedEqual;
    try std.testing.expectEqual(@as(?i64, 42), meta.message_id);
}

test "telegram api parseForumTopicMeta extracts message thread id" {
    const meta = parseForumTopicMeta(
        std.testing.allocator,
        "{\"ok\":true,\"result\":{\"message_thread_id\":77}}",
    ) orelse return error.TestExpectedEqual;
    try std.testing.expectEqual(@as(i64, 77), meta.message_thread_id);
}

test "telegram api buildEditMessageTextBody includes html parse mode when requested" {
    const body = try Client.buildEditMessageTextBody(
        std.testing.allocator,
        "12345",
        42,
        "<blockquote>trace</blockquote>",
        null,
        "HTML",
    );
    defer std.testing.allocator.free(body);

    try std.testing.expect(std.mem.indexOf(u8, body, "\"parse_mode\":\"HTML\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"message_id\":42") != null);
}

test "telegram api buildEditMessageTextBody omits parse mode for plain edits" {
    const body = try Client.buildEditMessageTextBody(
        std.testing.allocator,
        "12345",
        42,
        "plain text",
        null,
        null,
    );
    defer std.testing.allocator.free(body);

    try std.testing.expect(std.mem.indexOf(u8, body, "\"parse_mode\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"text\":\"plain text\"") != null);
}

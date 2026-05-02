const std = @import("std");
const std_compat = @import("compat");
const root = @import("root.zig");
const http_util = @import("../http_util.zig");
const error_classify = @import("error_classify.zig");

fn finalizeStreamResult(
    allocator: std.mem.Allocator,
    accumulated: []const u8,
    stream_usage: ?root.TokenUsage,
) !root.StreamChatResult {
    var content: ?[]const u8 = null;
    var reasoning_content: ?[]const u8 = null;
    if (accumulated.len > 0) {
        const split = try root.splitThinkContent(allocator, accumulated);
        content = split.visible;
        reasoning_content = split.reasoning;
    }

    var usage = stream_usage orelse root.TokenUsage{};
    if (usage.completion_tokens == 0) {
        usage.completion_tokens = @intCast((accumulated.len + 3) / 4);
    }

    return .{
        .content = content,
        .reasoning_content = reasoning_content,
        .usage = usage,
        .model = "",
    };
}

fn isJsonObjectResponse(body: []const u8) bool {
    const trimmed = std.mem.trim(u8, body, " \t\r\n");
    return trimmed.len > 0 and trimmed[0] == '{';
}

pub fn rejectJsonOrHttpErrorResponse(allocator: std.mem.Allocator, status_code: u16, body: []const u8) !void {
    if (!isJsonObjectResponse(body)) {
        if (status_code >= 400) return error.ServerError;
        return;
    }

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, body, .{}) catch null;
    if (parsed) |pval| {
        defer pval.deinit();
        if (pval.value == .object) {
            if (error_classify.classifyKnownApiError(pval.value.object)) |kind| {
                return error_classify.kindToError(kind);
            }
        }
    }
    return error.ServerError;
}

/// Result of parsing a single SSE line.
pub const SseLineResult = union(enum) {
    /// Text delta content (owned, caller frees).
    delta: []const u8,
    /// Stream is complete ([DONE] sentinel).
    done: void,
    /// Token usage from a stream chunk.
    usage: root.TokenUsage,
    /// Line should be skipped (empty, comment, or no content).
    skip: void,
};

/// Parse a single SSE line in OpenAI streaming format.
///
/// Handles:
/// - `data: [DONE]` → `.done`
/// - `data: {JSON}` → extracts `choices[0].delta.content` → `.delta`
/// - Empty lines, comments (`:`) → `.skip`
pub fn parseSseLine(allocator: std.mem.Allocator, line: []const u8) !SseLineResult {
    const trimmed = std_compat.mem.trimRight(u8, line, "\r");

    if (trimmed.len == 0) return .skip;
    if (trimmed[0] == ':') return .skip;

    // SSE uses "data:" with an optional single leading space before the value.
    const prefix = "data:";
    if (!std.mem.startsWith(u8, trimmed, prefix)) return .skip;

    const data = if (trimmed.len > prefix.len and trimmed[prefix.len] == ' ')
        trimmed[prefix.len + 1 ..]
    else
        trimmed[prefix.len..];

    if (data.len == 0) return .skip;

    if (std.mem.eql(u8, data, "[DONE]")) return .done;

    const content = try extractDeltaContent(allocator, data) orelse {
        // No content delta — check for usage data (sent in the final chunk).
        if (extractStreamUsage(data)) |u| return .{ .usage = u };
        return .skip;
    };
    return .{ .delta = content };
}

/// Extract `usage` object from an OpenAI-compatible streaming chunk.
/// The final chunk typically has `choices:[]` and a top-level `usage` object.
fn extractStreamUsage(json_str: []const u8) ?root.TokenUsage {
    var buf: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const alloc = fba.allocator();

    const parsed = std.json.parseFromSlice(std.json.Value, alloc, json_str, .{}) catch
        return null;
    defer parsed.deinit();

    const obj = parsed.value.object;
    const usage_val = obj.get("usage") orelse return null;
    if (usage_val != .object) return null;

    var usage = root.TokenUsage{};
    if (usage_val.object.get("prompt_tokens")) |v| {
        if (v == .integer) usage.prompt_tokens = @intCast(v.integer);
    }
    if (usage_val.object.get("completion_tokens")) |v| {
        if (v == .integer) usage.completion_tokens = @intCast(v.integer);
    }
    if (usage_val.object.get("total_tokens")) |v| {
        if (v == .integer) usage.total_tokens = @intCast(v.integer);
    }
    return usage;
}

/// Extract visible streaming text from an SSE JSON payload.
/// Falls back to `delta.reasoning`, `delta.reasoning_content`, or
/// `delta.reasoning_details` when providers stream their thinking trace
/// separately and wraps it in think tags so higher layers can suppress it
/// from user-visible output.
/// Returns owned slice or null if no content found.
pub fn extractDeltaContent(allocator: std.mem.Allocator, json_str: []const u8) !?[]const u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_str, .{}) catch
        return error.InvalidSseJson;
    defer parsed.deinit();

    const obj = parsed.value.object;
    const choices = obj.get("choices") orelse return null;
    if (choices != .array or choices.array.items.len == 0) return null;

    const first = choices.array.items[0];
    if (first != .object) return null;

    const delta = first.object.get("delta") orelse return null;
    if (delta != .object) return null;

    if (delta.object.get("content")) |content| {
        if (content == .string and content.string.len > 0) {
            return try allocator.dupe(u8, content.string);
        }
    }

    if (delta.object.get("reasoning")) |reasoning| {
        if (reasoning == .string and reasoning.string.len > 0) {
            return try std.fmt.allocPrint(allocator, "<think>{s}</think>", .{reasoning.string});
        }
    }

    if (delta.object.get("reasoning_content")) |reasoning_content| {
        if (reasoning_content == .string and reasoning_content.string.len > 0) {
            const wrapped = try std.fmt.allocPrint(allocator, "<think>{s}</think>", .{reasoning_content.string});
            return wrapped;
        }
    }

    if (delta.object.get("reasoning_details")) |reasoning_details| {
        if (try root.extractReasoningTextFromDetails(allocator, reasoning_details)) |reasoning_text| {
            defer allocator.free(reasoning_text);
            return try std.fmt.allocPrint(allocator, "<think>{s}</think>", .{reasoning_text});
        }
    }

    return null;
}

/// Run a native HTTP SSE request and parse output line by line.
/// For each SSE delta, calls `callback(ctx, chunk)`.
/// Returns accumulated result after stream completes.
pub fn httpStream(
    allocator: std.mem.Allocator,
    url: []const u8,
    body: []const u8,
    auth_header: ?[]const u8,
    extra_headers: []const []const u8,
    timeout_secs: u64,
    callback: root.StreamCallback,
    ctx: *anyopaque,
) !root.StreamChatResult {
    const proxy = http_util.getProxyFromEnv(allocator) catch null;
    defer if (proxy) |p| allocator.free(p);

    const resolve_entry = try http_util.buildSafeResolveEntryForRemoteUrl(allocator, url);
    defer if (resolve_entry) |entry| allocator.free(entry);

    var headers: std.ArrayListUnmanaged(std.http.Header) = .empty;
    defer headers.deinit(allocator);
    try headers.append(allocator, .{ .name = "Content-Type", .value = "application/json" });
    if (auth_header) |auth| try http_util.appendHeaderLines(&headers, allocator, &.{auth});
    for (extra_headers) |hdr| try http_util.appendHeaderLines(&headers, allocator, &.{hdr});

    const response = try http_util.nativeHttpRequest(allocator, .{
        .method = .POST,
        .url = url,
        .payload = body,
        .headers = headers.items,
        .proxy = proxy,
        .timeout_secs = if (timeout_secs == 0) null else timeout_secs,
        .resolve_entry = resolve_entry,
        .max_response_bytes = 16 * 1024 * 1024,
        .fail_on_http_error = false,
    });
    defer response.deinit(allocator);

    try rejectJsonOrHttpErrorResponse(allocator, response.status_code, response.body);

    var accumulated: std.ArrayListUnmanaged(u8) = .empty;
    defer accumulated.deinit(allocator);

    var line_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer line_buf.deinit(allocator);

    var saw_done = false;
    var stream_usage: ?root.TokenUsage = null;

    for (response.body) |byte| {
        if (saw_done) break;
        if (byte == '\n') {
            const result = parseSseLine(allocator, line_buf.items) catch {
                line_buf.clearRetainingCapacity();
                continue;
            };
            line_buf.clearRetainingCapacity();
            switch (result) {
                .delta => |text| {
                    defer allocator.free(text);
                    try accumulated.appendSlice(allocator, text);
                    callback(ctx, root.StreamChunk.textDelta(text));
                },
                .usage => |u| stream_usage = u,
                .done => saw_done = true,
                .skip => {},
            }
        } else {
            try line_buf.append(allocator, byte);
        }
    }

    if (!saw_done and line_buf.items.len > 0) {
        const trailing = parseSseLine(allocator, line_buf.items) catch null;
        line_buf.clearRetainingCapacity();
        if (trailing) |result| {
            switch (result) {
                .delta => |text| {
                    defer allocator.free(text);
                    try accumulated.appendSlice(allocator, text);
                    callback(ctx, root.StreamChunk.textDelta(text));
                },
                .usage => |u| stream_usage = u,
                .done => saw_done = true,
                .skip => {},
            }
        }
    }

    callback(ctx, root.StreamChunk.finalChunk());
    return finalizeStreamResult(allocator, accumulated.items, stream_usage);
}

// ════════════════════════════════════════════════════════════════════════════
// Anthropic SSE Parsing
// ════════════════════════════════════════════════════════════════════════════

/// Result of parsing a single Anthropic SSE line.
pub const AnthropicSseResult = union(enum) {
    /// Remember this event type (caller tracks state).
    event: []const u8,
    /// Text delta content (owned, caller frees).
    delta: []const u8,
    /// Output token count from message_delta usage.
    usage: u32,
    /// Stream is complete (message_stop).
    done: void,
    /// Line should be skipped (empty, comment, or uninteresting event).
    skip: void,
};

/// Parse a single SSE line in Anthropic streaming format.
///
/// Anthropic SSE is stateful: `event:` lines set the context for subsequent `data:` lines.
/// The caller must track `current_event` across calls.
///
/// - `event: X` → `.event` (caller remembers X)
/// - `data: {JSON}` + current_event=="content_block_delta" → extracts `delta.text` → `.delta`
/// - `data: {JSON}` + current_event=="message_delta" → extracts `usage.output_tokens` → `.usage`
/// - `data: {JSON}` + current_event=="message_stop" → `.done`
/// - Everything else → `.skip`
pub fn parseAnthropicSseLine(allocator: std.mem.Allocator, line: []const u8, current_event: []const u8) !AnthropicSseResult {
    const trimmed = std_compat.mem.trimRight(u8, line, "\r");

    if (trimmed.len == 0) return .skip;
    if (trimmed[0] == ':') return .skip;

    // Handle "event: TYPE" lines
    const event_prefix = "event: ";
    if (std.mem.startsWith(u8, trimmed, event_prefix)) {
        return .{ .event = trimmed[event_prefix.len..] };
    }

    // Handle "data: {JSON}" lines
    const data_prefix = "data: ";
    if (!std.mem.startsWith(u8, trimmed, data_prefix)) return .skip;

    const data = trimmed[data_prefix.len..];

    if (std.mem.eql(u8, current_event, "message_stop")) return .done;

    if (std.mem.eql(u8, current_event, "content_block_delta")) {
        const text = try extractAnthropicDelta(allocator, data) orelse return .skip;
        return .{ .delta = text };
    }

    if (std.mem.eql(u8, current_event, "message_delta")) {
        const tokens = try extractAnthropicUsage(data) orelse return .skip;
        return .{ .usage = tokens };
    }

    return .skip;
}

/// Extract `delta.text` from an Anthropic content_block_delta JSON payload.
/// Returns owned slice or null if not a text_delta.
pub fn extractAnthropicDelta(allocator: std.mem.Allocator, json_str: []const u8) !?[]const u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_str, .{}) catch
        return error.InvalidSseJson;
    defer parsed.deinit();

    const obj = parsed.value.object;
    const delta = obj.get("delta") orelse return null;
    if (delta != .object) return null;

    const dtype = delta.object.get("type") orelse return null;
    if (dtype != .string or !std.mem.eql(u8, dtype.string, "text_delta")) return null;

    const text = delta.object.get("text") orelse return null;
    if (text != .string) return null;
    if (text.string.len == 0) return null;

    return try allocator.dupe(u8, text.string);
}

/// Extract `usage.output_tokens` from an Anthropic message_delta JSON payload.
/// Returns token count or null if not present.
pub fn extractAnthropicUsage(json_str: []const u8) !?u32 {
    // Use a stack buffer for parsing to avoid needing an allocator
    var buf: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const allocator = fba.allocator();

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_str, .{}) catch
        return error.InvalidSseJson;
    defer parsed.deinit();

    const obj = parsed.value.object;
    const usage = obj.get("usage") orelse return null;
    if (usage != .object) return null;

    const output_tokens = usage.object.get("output_tokens") orelse return null;
    if (output_tokens != .integer) return null;

    return @intCast(output_tokens.integer);
}

/// Run a native HTTP SSE request for Anthropic and parse output line by line.
///
/// Similar to `httpStream()` but uses stateful Anthropic SSE parsing.
/// `headers` is a slice of pre-formatted header strings (e.g. "x-api-key: sk-...").
pub fn httpStreamAnthropic(
    allocator: std.mem.Allocator,
    url: []const u8,
    body: []const u8,
    headers: []const []const u8,
    callback: root.StreamCallback,
    ctx: *anyopaque,
) !root.StreamChatResult {
    const proxy = http_util.getProxyFromEnv(allocator) catch null;
    defer if (proxy) |p| allocator.free(p);

    const resolve_entry = try http_util.buildSafeResolveEntryForRemoteUrl(allocator, url);
    defer if (resolve_entry) |entry| allocator.free(entry);

    var native_headers: std.ArrayListUnmanaged(std.http.Header) = .empty;
    defer native_headers.deinit(allocator);
    try native_headers.append(allocator, .{ .name = "Content-Type", .value = "application/json" });
    for (headers) |hdr| try http_util.appendHeaderLines(&native_headers, allocator, &.{hdr});

    const response = try http_util.nativeHttpRequest(allocator, .{
        .method = .POST,
        .url = url,
        .payload = body,
        .headers = native_headers.items,
        .proxy = proxy,
        .resolve_entry = resolve_entry,
        .max_response_bytes = 16 * 1024 * 1024,
        .fail_on_http_error = false,
    });
    defer response.deinit(allocator);

    try rejectJsonOrHttpErrorResponse(allocator, response.status_code, response.body);

    var accumulated: std.ArrayListUnmanaged(u8) = .empty;
    defer accumulated.deinit(allocator);

    var line_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer line_buf.deinit(allocator);

    var current_event: []const u8 = "";
    var anthropic_usage: root.TokenUsage = .{};
    var saw_done = false;

    for (response.body) |byte| {
        if (saw_done) break;
        if (byte == '\n') {
            const result = parseAnthropicSseLine(allocator, line_buf.items, current_event) catch {
                line_buf.clearRetainingCapacity();
                continue;
            };
            switch (result) {
                .event => |ev| {
                    if (current_event.len > 0) allocator.free(@constCast(current_event));
                    current_event = allocator.dupe(u8, ev) catch "";
                },
                .delta => |text| {
                    defer allocator.free(text);
                    try accumulated.appendSlice(allocator, text);
                    callback(ctx, root.StreamChunk.textDelta(text));
                },
                .usage => |tokens| anthropic_usage.completion_tokens = tokens,
                .done => saw_done = true,
                .skip => {},
            }
            line_buf.clearRetainingCapacity();
        } else {
            try line_buf.append(allocator, byte);
        }
    }

    if (current_event.len > 0) allocator.free(@constCast(current_event));

    callback(ctx, root.StreamChunk.finalChunk());
    return finalizeStreamResult(allocator, accumulated.items, anthropic_usage);
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "parseSseLine valid delta" {
    const allocator = std.testing.allocator;
    const result = try parseSseLine(allocator, "data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}");
    switch (result) {
        .delta => |text| {
            defer allocator.free(text);
            try std.testing.expectEqualStrings("Hello", text);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "parseSseLine valid delta without optional space" {
    const allocator = std.testing.allocator;
    const result = try parseSseLine(allocator, "data:{\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}");
    switch (result) {
        .delta => |text| {
            defer allocator.free(text);
            try std.testing.expectEqualStrings("Hello", text);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "parseSseLine DONE sentinel" {
    const result = try parseSseLine(std.testing.allocator, "data: [DONE]");
    try std.testing.expect(result == .done);
}

test "parseSseLine DONE sentinel without optional space" {
    const result = try parseSseLine(std.testing.allocator, "data:[DONE]");
    try std.testing.expect(result == .done);
}

test "parseSseLine empty line" {
    const result = try parseSseLine(std.testing.allocator, "");
    try std.testing.expect(result == .skip);
}

test "parseSseLine comment" {
    const result = try parseSseLine(std.testing.allocator, ":keep-alive");
    try std.testing.expect(result == .skip);
}

test "parseSseLine empty data field" {
    const result = try parseSseLine(std.testing.allocator, "data:");
    try std.testing.expect(result == .skip);
}

test "parseSseLine delta without content" {
    const result = try parseSseLine(std.testing.allocator, "data: {\"choices\":[{\"delta\":{}}]}");
    try std.testing.expect(result == .skip);
}

test "parseSseLine empty choices" {
    const result = try parseSseLine(std.testing.allocator, "data: {\"choices\":[]}");
    try std.testing.expect(result == .skip);
}

test "parseSseLine invalid JSON" {
    try std.testing.expectError(error.InvalidSseJson, parseSseLine(std.testing.allocator, "data: not-json{{{"));
}

test "extractDeltaContent with content" {
    const allocator = std.testing.allocator;
    const result = (try extractDeltaContent(allocator, "{\"choices\":[{\"delta\":{\"content\":\"world\"}}]}")).?;
    defer allocator.free(result);
    try std.testing.expectEqualStrings("world", result);
}

test "extractDeltaContent without content" {
    const result = try extractDeltaContent(std.testing.allocator, "{\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}");
    try std.testing.expect(result == null);
}

test "extractDeltaContent empty content" {
    const result = try extractDeltaContent(std.testing.allocator, "{\"choices\":[{\"delta\":{\"content\":\"\"}}]}");
    try std.testing.expect(result == null);
}

test "extractDeltaContent falls back to reasoning_content when content empty" {
    const allocator = std.testing.allocator;
    const result = (try extractDeltaContent(allocator, "{\"choices\":[{\"delta\":{\"content\":\"\",\"reasoning_content\":\"step by step\"}}]}")).?;
    defer allocator.free(result);
    try std.testing.expectEqualStrings("<think>step by step</think>", result);
}

// Regression: OpenRouter's documented chat stream uses delta.reasoning.
test "extractDeltaContent falls back to reasoning when content missing" {
    const allocator = std.testing.allocator;
    const result = (try extractDeltaContent(allocator, "{\"choices\":[{\"delta\":{\"reasoning\":\"step by step\"}}]}")).?;
    defer allocator.free(result);
    try std.testing.expectEqualStrings("<think>step by step</think>", result);
}

test "extractDeltaContent falls back to reasoning_content when content missing" {
    const allocator = std.testing.allocator;
    const result = (try extractDeltaContent(allocator, "{\"choices\":[{\"delta\":{\"reasoning_content\":\"step by step\"}}]}")).?;
    defer allocator.free(result);
    try std.testing.expectEqualStrings("<think>step by step</think>", result);
}

// Regression: OpenRouter's current normalized streaming shape uses reasoning_details.
test "extractDeltaContent falls back to reasoning_details when content missing" {
    const allocator = std.testing.allocator;
    const result = (try extractDeltaContent(
        allocator,
        "{\"choices\":[{\"delta\":{\"reasoning_details\":[{\"type\":\"reasoning.summary\",\"summary\":\"plan\"},{\"type\":\"reasoning.text\",\"text\":\"step by step\"}]}}]}",
    )).?;
    defer allocator.free(result);
    try std.testing.expectEqualStrings("<think>plan\nstep by step</think>", result);
}

test "extractDeltaContent prefers visible content over reasoning_content" {
    const allocator = std.testing.allocator;
    const result = (try extractDeltaContent(allocator, "{\"choices\":[{\"delta\":{\"content\":\"final answer\",\"reasoning_content\":\"private\"}}]}")).?;
    defer allocator.free(result);
    try std.testing.expectEqualStrings("final answer", result);
}

test "extractDeltaContent empty reasoning_content returns null" {
    const result = try extractDeltaContent(std.testing.allocator, "{\"choices\":[{\"delta\":{\"reasoning_content\":\"\"}}]}");
    try std.testing.expect(result == null);
}

test "StreamChunk textDelta token estimate" {
    const chunk = root.StreamChunk.textDelta("12345678");
    try std.testing.expect(chunk.token_count == 2);
    try std.testing.expect(!chunk.is_final);
    try std.testing.expectEqualStrings("12345678", chunk.delta);
}

test "StreamChunk finalChunk" {
    const chunk = root.StreamChunk.finalChunk();
    try std.testing.expect(chunk.is_final);
    try std.testing.expectEqualStrings("", chunk.delta);
    try std.testing.expect(chunk.token_count == 0);
}

test "native migration streams OpenAI-compatible SSE through http helper" {
    const allocator = std.testing.allocator;
    const handler = struct {
        fn handle(alloc: std.mem.Allocator, request: http_util.NativeHttpRequest) anyerror!http_util.NativeHttpResponse {
            try std.testing.expectEqual(std.http.Method.POST, request.method);
            try std.testing.expectEqualStrings("http://127.0.0.1:11434/v1/chat/completions", request.url);
            try std.testing.expectEqualStrings("{\"stream\":true}", request.payload.?);
            try std.testing.expect(!request.fail_on_http_error);
            try std.testing.expectEqual(@as(?u64, 9), request.timeout_secs);
            try std.testing.expectEqual(@as(usize, 3), request.headers.len);
            try std.testing.expectEqualStrings("Content-Type", request.headers[0].name);
            try std.testing.expectEqualStrings("application/json", request.headers[0].value);
            try std.testing.expectEqualStrings("Authorization", request.headers[1].name);
            try std.testing.expectEqualStrings("Bearer test", request.headers[1].value);
            try std.testing.expectEqualStrings("X-Test", request.headers[2].name);
            try std.testing.expectEqualStrings("yes", request.headers[2].value);
            const body =
                "data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n" ++
                "data: {\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}\n" ++
                "data: [DONE]\n";
            return .{ .status_code = 200, .body = try alloc.dupe(u8, body) };
        }
    }.handle;

    http_util.setTestNativeHttpHandler(handler);
    defer http_util.setTestNativeHttpHandler(null);

    const Capture = struct {
        allocator: std.mem.Allocator,
        text: std.ArrayListUnmanaged(u8) = .empty,
        final_seen: bool = false,

        fn onChunk(ctx: *anyopaque, chunk: root.StreamChunk) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            if (chunk.is_final) {
                self.final_seen = true;
                return;
            }
            self.text.appendSlice(self.allocator, chunk.delta) catch {};
        }
    };

    var capture = Capture{ .allocator = allocator };
    defer capture.text.deinit(allocator);

    const result = try httpStream(
        allocator,
        "http://127.0.0.1:11434/v1/chat/completions",
        "{\"stream\":true}",
        "Authorization: Bearer test",
        &.{"X-Test: yes"},
        9,
        Capture.onChunk,
        @ptrCast(&capture),
    );
    defer if (result.content) |content| allocator.free(content);
    defer if (result.reasoning_content) |reasoning| allocator.free(reasoning);

    try std.testing.expect(capture.final_seen);
    try std.testing.expectEqualStrings("Hello", capture.text.items);
    try std.testing.expectEqualStrings("Hello", result.content.?);
}

test "native migration streams Anthropic SSE through http helper" {
    const allocator = std.testing.allocator;
    const handler = struct {
        fn handle(alloc: std.mem.Allocator, request: http_util.NativeHttpRequest) anyerror!http_util.NativeHttpResponse {
            try std.testing.expectEqual(std.http.Method.POST, request.method);
            try std.testing.expectEqualStrings("http://127.0.0.1:11434/v1/messages", request.url);
            try std.testing.expectEqualStrings("{\"stream\":true}", request.payload.?);
            try std.testing.expect(!request.fail_on_http_error);
            try std.testing.expectEqual(@as(usize, 2), request.headers.len);
            try std.testing.expectEqualStrings("Content-Type", request.headers[0].name);
            try std.testing.expectEqualStrings("application/json", request.headers[0].value);
            try std.testing.expectEqualStrings("x-api-key", request.headers[1].name);
            try std.testing.expectEqualStrings("test-key", request.headers[1].value);
            const body =
                "event: content_block_delta\n" ++
                "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"Hi\"}}\n" ++
                "event: message_delta\n" ++
                "data: {\"type\":\"message_delta\",\"delta\":{},\"usage\":{\"output_tokens\":7}}\n" ++
                "event: message_stop\n" ++
                "data: {\"type\":\"message_stop\"}\n";
            return .{ .status_code = 200, .body = try alloc.dupe(u8, body) };
        }
    }.handle;

    http_util.setTestNativeHttpHandler(handler);
    defer http_util.setTestNativeHttpHandler(null);

    const Capture = struct {
        allocator: std.mem.Allocator,
        text: std.ArrayListUnmanaged(u8) = .empty,
        final_seen: bool = false,

        fn onChunk(ctx: *anyopaque, chunk: root.StreamChunk) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            if (chunk.is_final) {
                self.final_seen = true;
                return;
            }
            self.text.appendSlice(self.allocator, chunk.delta) catch {};
        }
    };

    var capture = Capture{ .allocator = allocator };
    defer capture.text.deinit(allocator);

    const result = try httpStreamAnthropic(
        allocator,
        "http://127.0.0.1:11434/v1/messages",
        "{\"stream\":true}",
        &.{"x-api-key: test-key"},
        Capture.onChunk,
        @ptrCast(&capture),
    );
    defer if (result.content) |content| allocator.free(content);
    defer if (result.reasoning_content) |reasoning| allocator.free(reasoning);

    try std.testing.expect(capture.final_seen);
    try std.testing.expectEqualStrings("Hi", capture.text.items);
    try std.testing.expectEqualStrings("Hi", result.content.?);
    try std.testing.expectEqual(@as(u32, 7), result.usage.completion_tokens);
}

test "native migration stream classifies json error body after http status failure" {
    const allocator = std.testing.allocator;
    const handler = struct {
        fn handle(alloc: std.mem.Allocator, request: http_util.NativeHttpRequest) anyerror!http_util.NativeHttpResponse {
            try std.testing.expect(!request.fail_on_http_error);
            return .{
                .status_code = 429,
                .body = try alloc.dupe(u8, "{\"error\":{\"message\":\"rate limit exceeded\",\"type\":\"rate_limit_error\",\"code\":\"rate_limit_exceeded\"}}"),
            };
        }
    }.handle;

    http_util.setTestNativeHttpHandler(handler);
    defer http_util.setTestNativeHttpHandler(null);

    var callback_ctx: usize = 0;
    try std.testing.expectError(
        error.RateLimited,
        httpStream(
            allocator,
            "http://127.0.0.1:11434/v1/chat/completions",
            "{\"stream\":true}",
            null,
            &.{},
            9,
            struct {
                fn onChunk(_: *anyopaque, _: root.StreamChunk) void {}
            }.onChunk,
            @ptrCast(&callback_ctx),
        ),
    );
}

// ── Anthropic SSE Tests ─────────────────────────────────────────

test "parseAnthropicSseLine event line returns event" {
    const result = try parseAnthropicSseLine(std.testing.allocator, "event: content_block_delta", "");
    switch (result) {
        .event => |ev| try std.testing.expectEqualStrings("content_block_delta", ev),
        else => return error.TestUnexpectedResult,
    }
}

test "parseAnthropicSseLine data with content_block_delta returns delta" {
    const allocator = std.testing.allocator;
    const json = "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}";
    const result = try parseAnthropicSseLine(allocator, json, "content_block_delta");
    switch (result) {
        .delta => |text| {
            defer allocator.free(text);
            try std.testing.expectEqualStrings("Hello", text);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "parseAnthropicSseLine data with message_delta returns usage" {
    const json = "data: {\"type\":\"message_delta\",\"delta\":{},\"usage\":{\"output_tokens\":42}}";
    const result = try parseAnthropicSseLine(std.testing.allocator, json, "message_delta");
    switch (result) {
        .usage => |tokens| try std.testing.expect(tokens == 42),
        else => return error.TestUnexpectedResult,
    }
}

test "parseAnthropicSseLine data with message_stop returns done" {
    const result = try parseAnthropicSseLine(std.testing.allocator, "data: {\"type\":\"message_stop\"}", "message_stop");
    try std.testing.expect(result == .done);
}

test "parseAnthropicSseLine empty line returns skip" {
    const result = try parseAnthropicSseLine(std.testing.allocator, "", "");
    try std.testing.expect(result == .skip);
}

test "parseAnthropicSseLine comment returns skip" {
    const result = try parseAnthropicSseLine(std.testing.allocator, ":keep-alive", "");
    try std.testing.expect(result == .skip);
}

test "parseAnthropicSseLine data with unknown event returns skip" {
    const json = "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_123\"}}";
    const result = try parseAnthropicSseLine(std.testing.allocator, json, "message_start");
    try std.testing.expect(result == .skip);
}

test "extractAnthropicDelta correct JSON returns text" {
    const allocator = std.testing.allocator;
    const json = "{\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"world\"}}";
    const result = (try extractAnthropicDelta(allocator, json)).?;
    defer allocator.free(result);
    try std.testing.expectEqualStrings("world", result);
}

test "extractAnthropicDelta without text returns null" {
    const json = "{\"type\":\"content_block_delta\",\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{}\"}}";
    const result = try extractAnthropicDelta(std.testing.allocator, json);
    try std.testing.expect(result == null);
}

test "extractAnthropicUsage correct JSON returns token count" {
    const json = "{\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":57}}";
    const result = (try extractAnthropicUsage(json)).?;
    try std.testing.expect(result == 57);
}

// ── Stream Usage Extraction Tests ───────────────────────────────

test "extractStreamUsage returns full usage from final chunk" {
    const json = "{\"id\":\"chatcmpl-abc\",\"choices\":[],\"usage\":{\"prompt_tokens\":100,\"completion_tokens\":263,\"total_tokens\":363}}";
    const usage = extractStreamUsage(json).?;
    try std.testing.expectEqual(@as(u32, 100), usage.prompt_tokens);
    try std.testing.expectEqual(@as(u32, 263), usage.completion_tokens);
    try std.testing.expectEqual(@as(u32, 363), usage.total_tokens);
}

test "extractStreamUsage returns null for chunk without usage" {
    const json = "{\"id\":\"chatcmpl-abc\",\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}";
    try std.testing.expect(extractStreamUsage(json) == null);
}

test "extractStreamUsage returns null for invalid JSON" {
    try std.testing.expect(extractStreamUsage("not-json{{{") == null);
}

test "finalizeStreamResult separates think blocks into reasoning content" {
    const result = try finalizeStreamResult(
        std.testing.allocator,
        "<think>private trace</think>Visible answer",
        .{ .completion_tokens = 4, .total_tokens = 4 },
    );
    defer {
        if (result.content) |content| std.testing.allocator.free(content);
        if (result.reasoning_content) |reasoning| std.testing.allocator.free(reasoning);
    }

    try std.testing.expectEqualStrings("Visible answer", result.content.?);
    try std.testing.expectEqualStrings("private trace", result.reasoning_content.?);
}

test "parseSseLine extracts usage from final chunk" {
    const allocator = std.testing.allocator;
    const line = "data: {\"id\":\"chatcmpl-abc\",\"choices\":[],\"usage\":{\"prompt_tokens\":50,\"completion_tokens\":20,\"total_tokens\":70}}";
    const result = try parseSseLine(allocator, line);
    switch (result) {
        .usage => |u| {
            try std.testing.expectEqual(@as(u32, 50), u.prompt_tokens);
            try std.testing.expectEqual(@as(u32, 20), u.completion_tokens);
            try std.testing.expectEqual(@as(u32, 70), u.total_tokens);
        },
        else => return error.TestUnexpectedResult,
    }
}

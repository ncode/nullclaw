//! Shared HTTP utilities backed by std.http.
//!
//! Provides native Zig HTTP client wrappers used by providers, channels, and
//! tools.

const std = @import("std");
const std_compat = @import("compat");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const AtomicBool = std.atomic.Value(bool);
const net_security = @import("net_security.zig");

threadlocal var thread_interrupt_flag: ?*const AtomicBool = null;
const DEFAULT_HTTP_GET_MAX_BYTES: usize = 4 * 1024 * 1024;
const DEFAULT_HTTP_POST_MAX_BYTES: usize = 8 * 1024 * 1024;

pub fn setThreadInterruptFlag(flag: ?*const AtomicBool) void {
    thread_interrupt_flag = flag;
}

pub fn currentThreadInterruptFlag() ?*const AtomicBool {
    return thread_interrupt_flag;
}

fn checkInterrupted() !void {
    if (thread_interrupt_flag) |flag| {
        if (flag.load(.acquire)) return error.HttpInterrupted;
    }
}

pub const HttpResponse = struct {
    status_code: u16,
    body: []u8,
};

pub const HttpResponseWithHeaders = struct {
    status_code: u16,
    headers: []u8,
    body: []u8,
};

pub const NativeHttpRequest = struct {
    method: std.http.Method,
    url: []const u8,
    payload: ?[]const u8 = null,
    payload_file_path: ?[]const u8 = null,
    headers: []const std.http.Header = &.{},
    proxy: ?[]const u8 = null,
    timeout_secs: ?u64 = null,
    resolve_entry: ?[]const u8 = null,
    max_response_bytes: usize,
    fail_on_http_error: bool = false,
    include_response_headers: bool = false,
    follow_redirects: bool = false,
};

pub const NativeHttpResponse = struct {
    status_code: u16,
    headers: []u8 = &.{},
    body: []u8,

    pub fn deinit(self: NativeHttpResponse, allocator: Allocator) void {
        if (self.headers.len > 0) allocator.free(self.headers);
        allocator.free(self.body);
    }
};

pub const NativeHttpHandler = *const fn (Allocator, NativeHttpRequest) anyerror!NativeHttpResponse;

threadlocal var test_native_http_handler: ?NativeHttpHandler = null;

pub fn setTestNativeHttpHandler(handler: ?NativeHttpHandler) void {
    if (!builtin.is_test) @panic("setTestNativeHttpHandler is test-only");
    test_native_http_handler = handler;
}

pub fn hasTestNativeHttpHandler() bool {
    if (!builtin.is_test) return false;
    return test_native_http_handler != null;
}

const proxy_env_var_names = [_][]const u8{
    "http_proxy",
    "HTTP_PROXY",
    "https_proxy",
    "HTTPS_PROXY",
    "all_proxy",
    "ALL_PROXY",
};
const http_proxy_env_var_names = [_][]const u8{
    "http_proxy",
    "HTTP_PROXY",
    "all_proxy",
    "ALL_PROXY",
};
const https_proxy_env_var_names = [_][]const u8{
    "https_proxy",
    "HTTPS_PROXY",
    "all_proxy",
    "ALL_PROXY",
};

pub const ProxyHttpClient = struct {
    proxy_arena: std.heap.ArenaAllocator,
    client: std.http.Client,

    pub fn init(allocator: Allocator) !ProxyHttpClient {
        var proxy_arena = std.heap.ArenaAllocator.init(allocator);
        errdefer proxy_arena.deinit();

        var client: std.http.Client = .{ .allocator = allocator, .io = std_compat.io() };
        errdefer client.deinit();

        try initClientDefaultProxies(&client, proxy_arena.allocator());

        return .{
            .proxy_arena = proxy_arena,
            .client = client,
        };
    }

    pub fn deinit(self: *ProxyHttpClient) void {
        self.client.deinit();
        self.proxy_arena.deinit();
        self.* = undefined;
    }
};

pub const SafeResolveEntryError = Allocator.Error || error{
    InvalidUrl,
    LocalAddressBlocked,
    HostResolutionFailed,
};

fn defaultPortForScheme(uri: std.Uri) ?u16 {
    if (uri.port) |port| return port;
    if (std.ascii.eqlIgnoreCase(uri.scheme, "https")) return 443;
    if (std.ascii.eqlIgnoreCase(uri.scheme, "http")) return 80;
    return null;
}

fn shouldUsePinnedResolveHost(host: []const u8) bool {
    return std.mem.indexOfScalar(u8, net_security.stripHostBrackets(host), ':') == null;
}

fn shouldUsePinnedResolve(host: []const u8, connect_host: []const u8) bool {
    return shouldUsePinnedResolveHost(host) and !std.mem.eql(u8, host, connect_host);
}

fn buildPinnedResolveEntry(
    allocator: Allocator,
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

/// Build an optional host:port:address pinning entry for remote provider requests.
/// Remote hosts are pinned to a concrete globally-routable address; explicit
/// local/private hosts are left untouched so intentional local providers still work.
pub fn buildSafeResolveEntryForRemoteUrl(
    allocator: Allocator,
    url: []const u8,
) SafeResolveEntryError!?[]u8 {
    const uri = std.Uri.parse(url) catch return error.InvalidUrl;
    const port = defaultPortForScheme(uri) orelse return error.InvalidUrl;
    const host = net_security.extractHost(url) orelse return error.InvalidUrl;

    if (net_security.isLocalHost(host)) return null;

    const connect_host = try net_security.resolveConnectHost(allocator, host, port);
    defer allocator.free(connect_host);

    if (!shouldUsePinnedResolve(host, connect_host)) return null;
    return try buildPinnedResolveEntry(allocator, host, port, connect_host);
}

fn parseTimeoutSeconds(raw: ?[]const u8) !?u64 {
    const value = raw orelse return null;
    const trimmed = std.mem.trim(u8, value, " \t\r\n");
    if (trimmed.len == 0) return null;
    const parsed = std.fmt.parseInt(u64, trimmed, 10) catch return error.HttpFailed;
    return if (parsed == 0) null else parsed;
}

pub fn splitHeaderLine(line: []const u8) !std.http.Header {
    const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.HttpFailed;
    const name = std.mem.trim(u8, line[0..colon], " \t\r\n");
    const value = std.mem.trim(u8, line[colon + 1 ..], " \t\r\n");
    if (name.len == 0) return error.HttpFailed;
    return .{ .name = name, .value = value };
}

pub fn appendHeaderLines(
    list: *std.ArrayListUnmanaged(std.http.Header),
    allocator: Allocator,
    headers: []const []const u8,
) !void {
    for (headers) |header_line| {
        try list.append(allocator, try splitHeaderLine(header_line));
    }
}

fn buildJsonHeaders(
    allocator: Allocator,
    content_type_header: []const u8,
    headers: []const []const u8,
) !std.ArrayListUnmanaged(std.http.Header) {
    var list: std.ArrayListUnmanaged(std.http.Header) = .empty;
    errdefer list.deinit(allocator);
    try list.append(allocator, try splitHeaderLine(content_type_header));
    try appendHeaderLines(&list, allocator, headers);
    return list;
}

fn validateNativeProxyScheme(proxy: []const u8) !void {
    const trimmed = std.mem.trim(u8, proxy, " \t\r\n");
    if (trimmed.len == 0) return;
    const scheme_end = std.mem.indexOf(u8, trimmed, "://") orelse return;
    const scheme = trimmed[0..scheme_end];
    if (std.ascii.eqlIgnoreCase(scheme, "http")) return;
    if (std.ascii.eqlIgnoreCase(scheme, "https")) return;
    return error.UnsupportedProxyScheme;
}

fn validateNativeProxyEnvMap(env_map: *const std_compat.process.EnvMap) !void {
    for (proxy_env_var_names) |name| {
        const raw_value = env_map.get(name) orelse continue;
        try validateNativeProxyScheme(raw_value);
    }
}

fn initClientWithOptionalProxy(allocator: Allocator, proxy: ?[]const u8) !ProxyHttpClient {
    if (proxy == null) return ProxyHttpClient.init(allocator);
    try validateNativeProxyScheme(proxy.?);

    var proxy_arena = std.heap.ArenaAllocator.init(allocator);
    errdefer proxy_arena.deinit();

    var client: std.http.Client = .{ .allocator = allocator, .io = std_compat.io() };
    errdefer client.deinit();

    var env_map = std_compat.process.EnvMap.init(proxy_arena.allocator());
    const trimmed = std.mem.trim(u8, proxy.?, " \t\r\n");
    if (trimmed.len > 0) {
        for (proxy_env_var_names) |name| {
            try env_map.put(name, trimmed);
        }
    }
    try client.initDefaultProxies(proxy_arena.allocator(), &env_map);

    return .{
        .proxy_arena = proxy_arena,
        .client = client,
    };
}

const ResolvePin = struct {
    host: []const u8,
    port: u16,
    connect_host: []const u8,
};

fn parseResolveEntry(entry: []const u8) !ResolvePin {
    const host_end = std.mem.indexOfScalar(u8, entry, ':') orelse return error.HttpParseError;
    const port_start = host_end + 1;
    const port_end_rel = std.mem.indexOfScalar(u8, entry[port_start..], ':') orelse return error.HttpParseError;
    const port_end = port_start + port_end_rel;
    const port = std.fmt.parseInt(u16, entry[port_start..port_end], 10) catch return error.HttpParseError;
    var connect_host = entry[port_end + 1 ..];
    if (connect_host.len >= 2 and connect_host[0] == '[' and connect_host[connect_host.len - 1] == ']') {
        connect_host = connect_host[1 .. connect_host.len - 1];
    }
    if (entry[0..host_end].len == 0 or connect_host.len == 0) return error.HttpParseError;
    return .{
        .host = entry[0..host_end],
        .port = port,
        .connect_host = connect_host,
    };
}

fn mapNativeHttpError(err: anyerror) anyerror {
    return switch (err) {
        error.UnknownHostName,
        error.TemporaryNameServerFailure,
        error.NameServerFailure,
        => error.HttpDnsError,

        error.ConnectionRefused,
        error.NetworkUnreachable,
        error.HostUnreachable,
        error.ConnectionTimedOut,
        error.ConnectionResetByPeer,
        => error.HttpConnectError,

        error.Timeout => error.HttpTimeout,

        error.TlsInitializationFailed,
        error.CertificateBundleLoadFailure,
        error.TlsCertificateNotVerified,
        error.TlsBadRecordMac,
        error.TlsBadLength,
        error.TlsUnexpectedMessage,
        error.TlsDecryptFailure,
        error.TlsAlert,
        => error.HttpTlsError,

        error.StreamTooLong,
        error.ReadFailed,
        => error.HttpReadError,

        error.WriteFailed => error.HttpWriteError,
        else => err,
    };
}

fn socketTimeoutForSeconds(timeout_secs: u64) std.posix.timeval {
    const zero_timeout = std.posix.timeval{ .sec = 0, .usec = 0 };
    const TimevalSecs = @TypeOf(zero_timeout.sec);
    return .{
        .sec = @intCast(@min(timeout_secs, @as(u64, std.math.maxInt(TimevalSecs)))),
        .usec = 0,
    };
}

fn applyConnectionSocketTimeout(connection: ?*std.http.Client.Connection, timeout_secs: ?u64) void {
    const seconds = timeout_secs orelse return;
    if (seconds == 0) return;
    if (comptime builtin.os.tag == .windows) return;

    const timeout = socketTimeoutForSeconds(seconds);
    const bytes = std.mem.toBytes(timeout);
    const conn = connection orelse return;
    const handle = conn.stream_reader.stream.socket.handle;

    if (@hasDecl(std.posix.SO, "RCVTIMEO")) {
        std.posix.setsockopt(handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, &bytes) catch {};
    }
    if (@hasDecl(std.posix.SO, "SNDTIMEO")) {
        std.posix.setsockopt(handle, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, &bytes) catch {};
    }
}

fn deadlineFromTimeoutSeconds(timeout_secs: ?u64) ?i128 {
    const seconds = timeout_secs orelse return null;
    if (seconds == 0) return null;

    const now = std_compat.time.nanoTimestamp();
    const ns_per_s = @as(i128, std.time.ns_per_s);
    const remaining_ns = std.math.maxInt(i128) - now;
    const max_seconds = if (remaining_ns <= 0)
        0
    else
        @divTrunc(remaining_ns, ns_per_s);
    const clamped_seconds = @min(@as(i128, @intCast(seconds)), max_seconds);
    return now + clamped_seconds * ns_per_s;
}

fn checkDeadline(deadline_ns: ?i128) !void {
    const deadline = deadline_ns orelse return;
    if (std_compat.time.nanoTimestamp() >= deadline) return error.HttpTimeout;
}

fn appendResponseHeaders(
    allocator: Allocator,
    response_head: std.http.Client.Response.Head,
) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);

    try out.print(allocator, "HTTP/1.1 {d} {s}", .{
        @intFromEnum(response_head.status),
        response_head.reason,
    });

    var it = response_head.iterateHeaders();
    while (it.next()) |header| {
        try out.appendSlice(allocator, "\r\n");
        try out.appendSlice(allocator, header.name);
        try out.appendSlice(allocator, ": ");
        try out.appendSlice(allocator, header.value);
    }
    return out.toOwnedSlice(allocator);
}

fn requestConnectionForResolve(
    client: *std.http.Client,
    uri: std.Uri,
    resolve_entry: ?[]const u8,
    proxy: ?[]const u8,
) !?*std.http.Client.Connection {
    if (resolve_entry == null or proxy != null) return null;

    const pin = try parseResolveEntry(resolve_entry.?);
    const protocol = std.http.Client.Protocol.fromUri(uri) orelse return error.HttpFailed;
    if (shouldPreloadTlsForPinnedResolve(uri, resolve_entry, proxy)) {
        try ensureClientTlsReady(client);
    }

    var uri_host_buf: [std.Io.net.HostName.max_len]u8 = undefined;
    const uri_host = try uri.getHost(&uri_host_buf);
    const connect_host = try std.Io.net.HostName.init(pin.connect_host);

    return try client.connectTcpOptions(.{
        .host = connect_host,
        .port = pin.port,
        .protocol = protocol,
        .proxied_host = uri_host,
        .proxied_port = pin.port,
    });
}

fn shouldPreloadTlsForPinnedResolve(uri: std.Uri, resolve_entry: ?[]const u8, proxy: ?[]const u8) bool {
    if (resolve_entry == null or proxy != null) return false;
    const protocol = std.http.Client.Protocol.fromUri(uri) orelse return false;
    return protocol == .tls;
}

fn ensureClientTlsReady(client: *std.http.Client) !void {
    if (comptime std.http.Client.disable_tls) return error.HttpTlsError;

    const io = client.io;
    {
        try client.ca_bundle_lock.lockShared(io);
        defer client.ca_bundle_lock.unlockShared(io);
        if (client.now != null) return;
    }

    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(client.allocator);

    const now = std.Io.Clock.real.now(io);
    bundle.rescan(client.allocator, io, now) catch |err| switch (err) {
        error.Canceled => |e| return e,
        else => return error.CertificateBundleLoadFailure,
    };

    try client.ca_bundle_lock.lock(io);
    defer client.ca_bundle_lock.unlock(io);
    if (client.now == null) {
        client.now = now;
        std.mem.swap(std.crypto.Certificate.Bundle, &client.ca_bundle, &bundle);
    }
}

fn readResponseBody(
    allocator: Allocator,
    client: *std.http.Client,
    response: *std.http.Client.Response,
    max_response_bytes: usize,
    deadline_ns: ?i128,
) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);

    const decompress_buffer: []u8 = switch (response.head.content_encoding) {
        .identity => &.{},
        .zstd => try client.allocator.alloc(u8, std.compress.zstd.default_window_len),
        .deflate, .gzip => try client.allocator.alloc(u8, std.compress.flate.max_window_len),
        .compress => return error.HttpReadError,
    };
    defer if (response.head.content_encoding != .identity) client.allocator.free(decompress_buffer);

    var transfer_buffer: [64]u8 = undefined;
    var decompress: std.http.Decompress = undefined;
    const reader = response.readerDecompressing(&transfer_buffer, &decompress, decompress_buffer);

    var chunk: [8192]u8 = undefined;
    while (true) {
        try checkInterrupted();
        try checkDeadline(deadline_ns);
        const n = reader.readSliceShort(&chunk) catch |err| switch (err) {
            else => return error.HttpReadError,
        };
        if (n == 0) break;
        if (body.items.len + n > max_response_bytes) return error.HttpReadError;
        try body.appendSlice(allocator, chunk[0..n]);
    }

    return body.toOwnedSlice(allocator);
}

fn writeRequestPayloadFromFile(
    request: *std.http.Client.Request,
    file_path: []const u8,
    deadline_ns: ?i128,
) !void {
    const file = std_compat.fs.openFileAbsolute(file_path, .{}) catch return error.HttpReadError;
    defer file.close();

    const stat = file.stat() catch return error.HttpReadError;
    request.transfer_encoding = .{ .content_length = stat.size };
    var body_writer = request.sendBodyUnflushed(&.{}) catch |err| return mapNativeHttpError(err);

    var buf: [32 * 1024]u8 = undefined;
    while (true) {
        try checkInterrupted();
        try checkDeadline(deadline_ns);
        const n = file.read(&buf) catch return error.HttpReadError;
        if (n == 0) break;
        body_writer.writer.writeAll(buf[0..n]) catch |err| return mapNativeHttpError(err);
    }
    body_writer.end() catch |err| return mapNativeHttpError(err);
    request.connection.?.flush() catch |err| return mapNativeHttpError(err);
}

fn writeRequestPayload(
    request: *std.http.Client.Request,
    payload: ?[]const u8,
    payload_file_path: ?[]const u8,
    deadline_ns: ?i128,
) !void {
    if (payload != null and payload_file_path != null) return error.HttpFailed;

    if (payload) |body| {
        try checkDeadline(deadline_ns);
        request.transfer_encoding = .{ .content_length = body.len };
        var body_writer = request.sendBodyUnflushed(&.{}) catch |err| return mapNativeHttpError(err);
        body_writer.writer.writeAll(body) catch |err| return mapNativeHttpError(err);
        body_writer.end() catch |err| return mapNativeHttpError(err);
        request.connection.?.flush() catch |err| return mapNativeHttpError(err);
        return;
    }

    if (payload_file_path) |path| {
        try writeRequestPayloadFromFile(request, path, deadline_ns);
        return;
    }

    try checkDeadline(deadline_ns);
    request.sendBodiless() catch |err| return mapNativeHttpError(err);
}

fn finalizeNativeHttpResponse(
    allocator: Allocator,
    request: NativeHttpRequest,
    response: NativeHttpResponse,
) !NativeHttpResponse {
    if (request.fail_on_http_error and response.status_code >= 400) {
        response.deinit(allocator);
        return error.HttpFailed;
    }
    if (response.body.len > request.max_response_bytes) {
        response.deinit(allocator);
        return error.HttpReadError;
    }
    return response;
}

fn runNativeHttpRequest(allocator: Allocator, request: NativeHttpRequest) !NativeHttpResponse {
    try checkInterrupted();
    const deadline_ns = deadlineFromTimeoutSeconds(request.timeout_secs);

    if (builtin.is_test) {
        if (test_native_http_handler) |handler| {
            return finalizeNativeHttpResponse(allocator, request, try handler(allocator, request));
        }
    }

    try checkInterrupted();
    var client = try initClientWithOptionalProxy(allocator, request.proxy);
    defer client.deinit();

    const uri = std.Uri.parse(request.url) catch return error.HttpFailed;
    try checkInterrupted();
    const connection = requestConnectionForResolve(&client.client, uri, request.resolve_entry, request.proxy) catch |err|
        return mapNativeHttpError(err);

    var redirect_buffer: [8192]u8 = undefined;
    const redirect_behavior: std.http.Client.Request.RedirectBehavior = if (request.follow_redirects and request.payload == null)
        @enumFromInt(3)
    else
        .unhandled;

    var req = client.client.request(request.method, uri, .{
        .extra_headers = request.headers,
        .redirect_behavior = redirect_behavior,
        .connection = connection,
        .keep_alive = false,
    }) catch |err| return mapNativeHttpError(err);
    defer req.deinit();
    applyConnectionSocketTimeout(req.connection, request.timeout_secs);

    try checkInterrupted();
    try checkDeadline(deadline_ns);
    try writeRequestPayload(&req, request.payload, request.payload_file_path, deadline_ns);

    try checkInterrupted();
    try checkDeadline(deadline_ns);
    var response = req.receiveHead(if (redirect_behavior == .unhandled) &.{} else &redirect_buffer) catch |err|
        return mapNativeHttpError(err);
    const status_code: u16 = @intFromEnum(response.head.status);

    if (request.fail_on_http_error and status_code >= 400) {
        return error.HttpFailed;
    }

    const headers = if (request.include_response_headers)
        try appendResponseHeaders(allocator, response.head)
    else
        try allocator.dupe(u8, "");
    errdefer allocator.free(headers);

    const body = readResponseBody(allocator, &client.client, &response, request.max_response_bytes, deadline_ns) catch |err|
        return mapNativeHttpError(err);
    try checkInterrupted();
    try checkDeadline(deadline_ns);

    return finalizeNativeHttpResponse(allocator, request, .{
        .status_code = status_code,
        .headers = headers,
        .body = body,
    });
}

pub fn nativeHttpRequest(allocator: Allocator, request: NativeHttpRequest) !NativeHttpResponse {
    return runNativeHttpRequest(allocator, request);
}

/// HTTP POST with optional proxy and timeout.
///
/// `headers` is a slice of header strings (e.g. `"Authorization: Bearer xxx"`).
/// `proxy` is an optional HTTP(S) proxy URL (e.g. `"http://host:port"`).
/// `max_time` is an optional timeout value in seconds as a string (e.g. `"300"`).
/// Returns the response body. Caller owns returned memory.
pub fn httpPostWithProxy(
    allocator: Allocator,
    url: []const u8,
    body: []const u8,
    headers: []const []const u8,
    proxy: ?[]const u8,
    max_time: ?[]const u8,
) ![]u8 {
    return httpPostWithProxyAndResolve(allocator, url, body, headers, proxy, max_time, null);
}

pub fn httpPostWithProxyAndResolve(
    allocator: Allocator,
    url: []const u8,
    body: []const u8,
    headers: []const []const u8,
    proxy: ?[]const u8,
    max_time: ?[]const u8,
    resolve_entry: ?[]const u8,
) ![]u8 {
    return httpRequestWithProxy(
        allocator,
        "POST",
        "Content-Type: application/json",
        url,
        body,
        headers,
        proxy,
        max_time,
        resolve_entry,
    );
}

/// HTTP POST with application/x-www-form-urlencoded body with optional proxy
/// and timeout.
pub fn httpPostFormWithProxy(
    allocator: Allocator,
    url: []const u8,
    body: []const u8,
    proxy: ?[]const u8,
    max_time: ?[]const u8,
) ![]u8 {
    return httpPostFormWithProxyAndResolve(allocator, url, body, proxy, max_time, null);
}

pub fn httpPostFormWithProxyAndResolve(
    allocator: Allocator,
    url: []const u8,
    body: []const u8,
    proxy: ?[]const u8,
    max_time: ?[]const u8,
    resolve_entry: ?[]const u8,
) ![]u8 {
    return httpRequestWithProxy(
        allocator,
        "POST",
        "Content-Type: application/x-www-form-urlencoded",
        url,
        body,
        &.{},
        proxy,
        max_time,
        resolve_entry,
    );
}

fn httpRequestWithProxy(
    allocator: Allocator,
    method: []const u8,
    content_type_header: []const u8,
    url: []const u8,
    body: []const u8,
    headers: []const []const u8,
    proxy: ?[]const u8,
    max_time: ?[]const u8,
    resolve_entry: ?[]const u8,
) ![]u8 {
    const http_method = std.meta.stringToEnum(std.http.Method, method) orelse return error.HttpFailed;
    var header_list = try buildJsonHeaders(allocator, content_type_header, headers);
    defer header_list.deinit(allocator);

    const response = try runNativeHttpRequest(allocator, .{
        .method = http_method,
        .url = url,
        .payload = body,
        .headers = header_list.items,
        .proxy = proxy,
        .timeout_secs = try parseTimeoutSeconds(max_time),
        .resolve_entry = resolve_entry,
        .max_response_bytes = DEFAULT_HTTP_POST_MAX_BYTES,
        .fail_on_http_error = false,
    });
    defer if (response.headers.len > 0) allocator.free(response.headers);
    return response.body;
}

/// HTTP POST without proxy or timeout.
pub fn httpPost(allocator: Allocator, url: []const u8, body: []const u8, headers: []const []const u8) ![]u8 {
    return httpPostWithProxy(allocator, url, body, headers, null, null);
}

/// HTTP POST with application/x-www-form-urlencoded body.
///
/// `body` must already be percent-encoded form data (e.g. `"key=val&key2=val2"`).
/// Returns the response body. Caller owns returned memory.
pub fn httpPostForm(allocator: Allocator, url: []const u8, body: []const u8) ![]u8 {
    return httpPostFormWithProxy(allocator, url, body, null, null);
}

/// HTTP POST and include HTTP status code in response.
/// Caller owns `response.body`.
pub fn httpPostWithStatus(
    allocator: Allocator,
    url: []const u8,
    body: []const u8,
    headers: []const []const u8,
) !HttpResponse {
    return httpPostWithStatusAndTimeout(allocator, url, body, headers, null);
}

pub fn httpGetWithStatus(
    allocator: Allocator,
    url: []const u8,
    headers: []const []const u8,
) !HttpResponse {
    return httpGetWithStatusAndTimeout(allocator, url, headers, null);
}

/// HTTP POST and include HTTP status code in response, with optional timeout.
/// Caller owns `response.body`.
pub fn httpPostWithStatusAndTimeout(
    allocator: Allocator,
    url: []const u8,
    body: []const u8,
    headers: []const []const u8,
    max_time: ?[]const u8,
) !HttpResponse {
    return httpPostWithStatusAndTimeoutAndResolve(allocator, url, body, headers, max_time, null);
}

pub fn httpPostWithStatusAndTimeoutAndResolve(
    allocator: Allocator,
    url: []const u8,
    body: []const u8,
    headers: []const []const u8,
    max_time: ?[]const u8,
    resolve_entry: ?[]const u8,
) !HttpResponse {
    var header_list = try buildJsonHeaders(allocator, "Content-Type: application/json", headers);
    defer header_list.deinit(allocator);

    const response = try runNativeHttpRequest(allocator, .{
        .method = .POST,
        .url = url,
        .payload = body,
        .headers = header_list.items,
        .timeout_secs = try parseTimeoutSeconds(max_time),
        .resolve_entry = resolve_entry,
        .max_response_bytes = DEFAULT_HTTP_POST_MAX_BYTES,
        .fail_on_http_error = false,
    });
    defer if (response.headers.len > 0) allocator.free(response.headers);

    return .{
        .status_code = response.status_code,
        .body = response.body,
    };
}

/// HTTP POST and include HTTP status code and response headers, with optional
/// timeout.
/// Caller owns `response.headers` and `response.body`.
pub fn httpPostWithStatusHeadersAndTimeout(
    allocator: Allocator,
    url: []const u8,
    body: []const u8,
    headers: []const []const u8,
    max_time: ?[]const u8,
) !HttpResponseWithHeaders {
    return httpPostWithStatusHeadersAndTimeoutAndResolve(allocator, url, body, headers, max_time, null);
}

pub fn httpPostWithStatusHeadersAndTimeoutAndResolve(
    allocator: Allocator,
    url: []const u8,
    body: []const u8,
    headers: []const []const u8,
    max_time: ?[]const u8,
    resolve_entry: ?[]const u8,
) !HttpResponseWithHeaders {
    var header_list = try buildJsonHeaders(allocator, "Content-Type: application/json", headers);
    defer header_list.deinit(allocator);

    const response = try runNativeHttpRequest(allocator, .{
        .method = .POST,
        .url = url,
        .payload = body,
        .headers = header_list.items,
        .timeout_secs = try parseTimeoutSeconds(max_time),
        .resolve_entry = resolve_entry,
        .max_response_bytes = DEFAULT_HTTP_POST_MAX_BYTES,
        .fail_on_http_error = false,
        .include_response_headers = true,
    });

    return .{
        .status_code = response.status_code,
        .headers = response.headers,
        .body = response.body,
    };
}

pub fn httpGetWithStatusAndTimeout(
    allocator: Allocator,
    url: []const u8,
    headers: []const []const u8,
    max_time: ?[]const u8,
) !HttpResponse {
    return httpGetWithStatusAndTimeoutAndResolve(allocator, url, headers, max_time, null);
}

pub fn httpGetWithStatusAndTimeoutAndResolve(
    allocator: Allocator,
    url: []const u8,
    headers: []const []const u8,
    max_time: ?[]const u8,
    resolve_entry: ?[]const u8,
) !HttpResponse {
    var header_list: std.ArrayListUnmanaged(std.http.Header) = .empty;
    defer header_list.deinit(allocator);
    try appendHeaderLines(&header_list, allocator, headers);

    const response = try runNativeHttpRequest(allocator, .{
        .method = .GET,
        .url = url,
        .headers = header_list.items,
        .timeout_secs = try parseTimeoutSeconds(max_time),
        .resolve_entry = resolve_entry,
        .max_response_bytes = DEFAULT_HTTP_GET_MAX_BYTES,
        .fail_on_http_error = false,
    });
    defer if (response.headers.len > 0) allocator.free(response.headers);

    return .{
        .status_code = response.status_code,
        .body = response.body,
    };
}

/// HTTP PUT without proxy or timeout.
pub fn httpPut(allocator: Allocator, url: []const u8, body: []const u8, headers: []const []const u8) ![]u8 {
    return httpRequestWithProxy(
        allocator,
        "PUT",
        "Content-Type: application/json",
        url,
        body,
        headers,
        null,
        null,
        null,
    );
}

/// HTTP GET with optional proxy.
///
/// `headers` is a slice of header strings (e.g. `"Authorization: Bearer xxx"`).
/// `timeout_secs` sets the timeout in seconds. Returns the response body.
/// Caller owns returned memory.
fn httpGetWithProxyAndResolve(
    allocator: Allocator,
    url: []const u8,
    headers: []const []const u8,
    timeout_secs: []const u8,
    proxy: ?[]const u8,
    resolve_entry: ?[]const u8,
    max_bytes: usize,
) ![]u8 {
    var header_list: std.ArrayListUnmanaged(std.http.Header) = .empty;
    defer header_list.deinit(allocator);
    try appendHeaderLines(&header_list, allocator, headers);

    const response = try runNativeHttpRequest(allocator, .{
        .method = .GET,
        .url = url,
        .headers = header_list.items,
        .proxy = proxy,
        .timeout_secs = try parseTimeoutSeconds(timeout_secs),
        .resolve_entry = resolve_entry,
        .max_response_bytes = max_bytes,
        .fail_on_http_error = true,
    });
    defer if (response.headers.len > 0) allocator.free(response.headers);
    return response.body;
}

/// HTTP GET with optional proxy.
///
/// `headers` is a slice of header strings (e.g. `"Authorization: Bearer xxx"`).
/// `timeout_secs` sets the timeout in seconds. Returns the response body.
/// Caller owns returned memory.
pub fn httpGetWithProxy(
    allocator: Allocator,
    url: []const u8,
    headers: []const []const u8,
    timeout_secs: []const u8,
    proxy: ?[]const u8,
) ![]u8 {
    return httpGetWithProxyAndResolve(allocator, url, headers, timeout_secs, proxy, null, DEFAULT_HTTP_GET_MAX_BYTES);
}

/// HTTP GET with a pinned host mapping.
///
/// `resolve_entry` must be in host:port:address format.
pub fn httpGetWithResolve(
    allocator: Allocator,
    url: []const u8,
    headers: []const []const u8,
    timeout_secs: []const u8,
    resolve_entry: []const u8,
) ![]u8 {
    return httpGetWithProxyAndResolve(allocator, url, headers, timeout_secs, null, resolve_entry, DEFAULT_HTTP_GET_MAX_BYTES);
}

/// HTTP GET without proxy.
pub fn httpGet(allocator: Allocator, url: []const u8, headers: []const []const u8, timeout_secs: []const u8) ![]u8 {
    return httpGetWithProxy(allocator, url, headers, timeout_secs, null);
}

/// HTTP GET with a caller-provided response size cap.
pub fn httpGetMaxBytes(
    allocator: Allocator,
    url: []const u8,
    headers: []const []const u8,
    timeout_secs: []const u8,
    max_bytes: usize,
) ![]u8 {
    return httpGetWithProxyAndResolve(allocator, url, headers, timeout_secs, null, null, max_bytes);
}

/// Read proxy URL from standard environment variables.
/// Checks https_proxy/HTTPS_PROXY first, then http_proxy/HTTP_PROXY,
/// then all_proxy/ALL_PROXY.
/// Returns null if no proxy is set.
/// Caller owns returned memory.
var proxy_override_value: ?[]u8 = null;
var proxy_override_mutex: std_compat.sync.Mutex = .{};

pub const ProxyOverrideError = error{OutOfMemory};

/// Set process-wide proxy override from config.
/// When set, this value has higher priority than proxy environment variables.
pub fn setProxyOverride(proxy: ?[]const u8) ProxyOverrideError!void {
    proxy_override_mutex.lock();
    defer proxy_override_mutex.unlock();

    if (proxy_override_value) |existing| {
        std.heap.page_allocator.free(existing);
        proxy_override_value = null;
    }

    if (proxy) |raw| {
        const trimmed = std.mem.trim(u8, raw, " \t\r\n");
        if (trimmed.len == 0) return;
        proxy_override_value = try std.heap.page_allocator.dupe(u8, trimmed);
    }
}

fn normalizeProxyEnvValue(allocator: Allocator, val: []const u8) !?[]const u8 {
    const trimmed = std.mem.trim(u8, val, " \t\r\n");
    if (trimmed.len == 0) return null;
    return try allocator.dupe(u8, trimmed);
}

fn applyProxyOverrideToEnvMap(env_map: *std_compat.process.EnvMap) !bool {
    proxy_override_mutex.lock();
    defer proxy_override_mutex.unlock();

    const override = proxy_override_value orelse return false;
    for (proxy_env_var_names) |key| {
        try env_map.put(key, override);
    }
    return true;
}

fn putProxyEnvVarFromProcess(
    env_map: *std_compat.process.EnvMap,
    allocator: Allocator,
    key: []const u8,
) !void {
    if (std_compat.process.getEnvVarOwned(allocator, key)) |raw_value| {
        defer allocator.free(raw_value);
        if (try normalizeProxyEnvValue(allocator, raw_value)) |proxy| {
            try env_map.put(key, proxy);
        }
    } else |_| {}
}

fn buildProxyEnvMapFromProcess(allocator: Allocator) !std_compat.process.EnvMap {
    var env_map = std_compat.process.EnvMap.init(allocator);
    errdefer env_map.deinit();

    for (proxy_env_var_names) |key| {
        try putProxyEnvVarFromProcess(&env_map, allocator, key);
    }
    _ = try applyProxyOverrideToEnvMap(&env_map);

    return env_map;
}

fn getProxyFromEnvMap(
    allocator: Allocator,
    env_map: *const std_compat.process.EnvMap,
    env_vars: []const []const u8,
) !?[]const u8 {
    for (env_vars) |var_name| {
        const raw_value = env_map.get(var_name) orelse continue;
        if (try normalizeProxyEnvValue(allocator, raw_value)) |proxy| {
            return proxy;
        }
    }
    return null;
}

fn initClientDefaultProxiesFromEnvMap(
    client: *std.http.Client,
    arena: Allocator,
    env_map: *const std_compat.process.EnvMap,
) !void {
    var merged_env_map = try env_map.clone(arena);
    _ = try applyProxyOverrideToEnvMap(&merged_env_map);
    try validateNativeProxyEnvMap(&merged_env_map);
    try client.initDefaultProxies(arena, &merged_env_map);
}

pub fn initClientDefaultProxies(client: *std.http.Client, arena: Allocator) !void {
    var env_map = try buildProxyEnvMapFromProcess(arena);
    try validateNativeProxyEnvMap(&env_map);
    try client.initDefaultProxies(arena, &env_map);
}

pub fn getProxyFromEnv(allocator: Allocator) !?[]const u8 {
    var env_map = try buildProxyEnvMapFromProcess(allocator);
    defer env_map.deinit();

    if (try getProxyFromEnvMap(allocator, &env_map, &https_proxy_env_var_names)) |proxy| {
        return proxy;
    }
    return try getProxyFromEnvMap(allocator, &env_map, &http_proxy_env_var_names);
}

/// HTTP GET for SSE (Server-Sent Events).
pub fn httpGetSse(
    allocator: Allocator,
    url: []const u8,
    timeout_secs: []const u8,
) ![]u8 {
    const response = try nativeHttpRequest(allocator, .{
        .method = .GET,
        .url = url,
        .headers = &.{.{ .name = "Accept", .value = "text/event-stream" }},
        .timeout_secs = try parseTimeoutSeconds(timeout_secs),
        .max_response_bytes = 4 * 1024 * 1024,
        .fail_on_http_error = true,
    });
    defer if (response.headers.len > 0) allocator.free(response.headers);
    return response.body;
}

// ── Tests ───────────────────────────────────────────────────────────

test "native http helpers expose native request surface" {
    const allocator = std.testing.allocator;
    const handler = struct {
        fn handle(alloc: Allocator, request: NativeHttpRequest) anyerror!NativeHttpResponse {
            try std.testing.expectEqual(std.http.Method.POST, request.method);
            try std.testing.expectEqualStrings("https://api.example.test/native", request.url);
            try std.testing.expectEqualStrings("{\"ok\":true}", request.payload.?);
            try std.testing.expectEqual(@as(?u64, 11), request.timeout_secs);
            try std.testing.expectEqualStrings("Content-Type", request.headers[0].name);
            try std.testing.expectEqualStrings("application/json", request.headers[0].value);
            return .{ .status_code = 200, .body = try alloc.dupe(u8, "native") };
        }
    }.handle;

    setTestNativeHttpHandler(handler);
    defer setTestNativeHttpHandler(null);

    const body = try httpPostWithProxy(
        allocator,
        "https://api.example.test/native",
        "{\"ok\":true}",
        &.{},
        null,
        "11",
    );
    defer allocator.free(body);

    try std.testing.expectEqualStrings("native", body);
}

test "native migration preserves json post helper request semantics" {
    const allocator = std.testing.allocator;
    const handler = struct {
        fn handle(alloc: Allocator, request: NativeHttpRequest) anyerror!NativeHttpResponse {
            try std.testing.expectEqual(std.http.Method.POST, request.method);
            try std.testing.expectEqualStrings("https://api.example.test/v1/messages", request.url);
            try std.testing.expectEqualStrings("{\"ok\":true}", request.payload.?);
            try std.testing.expect(request.fail_on_http_error == false);
            try std.testing.expect(request.max_response_bytes >= DEFAULT_HTTP_POST_MAX_BYTES);
            try std.testing.expectEqual(@as(?u64, 7), request.timeout_secs);
            try std.testing.expectEqualStrings("socks5://127.0.0.1:1080", request.proxy.?);
            try std.testing.expectEqual(@as(usize, 2), request.headers.len);
            try std.testing.expectEqualStrings("Content-Type", request.headers[0].name);
            try std.testing.expectEqualStrings("application/json", request.headers[0].value);
            try std.testing.expectEqualStrings("Authorization", request.headers[1].name);
            try std.testing.expectEqualStrings("Bearer test", request.headers[1].value);
            return .{ .status_code = 500, .body = try alloc.dupe(u8, "server kept body") };
        }
    }.handle;

    setTestNativeHttpHandler(handler);
    defer setTestNativeHttpHandler(null);

    const body = try httpPostWithProxy(
        allocator,
        "https://api.example.test/v1/messages",
        "{\"ok\":true}",
        &.{"Authorization: Bearer test"},
        "socks5://127.0.0.1:1080",
        "7",
    );
    defer allocator.free(body);

    // Regression: the legacy POST helper did not fail on HTTP status, so callers
    // still receive the response body even for non-2xx responses.
    try std.testing.expectEqualStrings("server kept body", body);
}

test "native migration preserves get fail-fast and max bytes semantics" {
    const allocator = std.testing.allocator;
    const State = struct {
        var calls: usize = 0;

        fn handle(alloc: Allocator, request: NativeHttpRequest) anyerror!NativeHttpResponse {
            calls += 1;
            try std.testing.expectEqual(std.http.Method.GET, request.method);
            try std.testing.expect(request.fail_on_http_error);
            try std.testing.expectEqual(@as(usize, 4), request.max_response_bytes);
            try std.testing.expectEqualStrings("Accept", request.headers[0].name);
            try std.testing.expectEqualStrings("application/json", request.headers[0].value);
            return .{ .status_code = 404, .body = try alloc.dupe(u8, "lost") };
        }
    };
    State.calls = 0;

    setTestNativeHttpHandler(State.handle);
    defer setTestNativeHttpHandler(null);

    // Regression: the legacy GET helper failed on HTTP 4xx/5xx statuses while
    // status-aware helpers keep the response body.
    try std.testing.expectError(
        error.HttpFailed,
        httpGetMaxBytes(allocator, "https://api.example.test/missing", &.{"Accept: application/json"}, "3", 4),
    );
    try std.testing.expectEqual(@as(usize, 1), State.calls);
}

test "native migration preserves status and response header helpers" {
    const allocator = std.testing.allocator;
    const handler = struct {
        fn handle(alloc: Allocator, request: NativeHttpRequest) anyerror!NativeHttpResponse {
            try std.testing.expectEqual(std.http.Method.POST, request.method);
            try std.testing.expect(request.include_response_headers);
            return .{
                .status_code = 201,
                .headers = try alloc.dupe(u8, "HTTP/1.1 201 Created\r\nx-request-id: req_123"),
                .body = try alloc.dupe(u8, "{\"id\":\"msg_1\"}"),
            };
        }
    }.handle;

    setTestNativeHttpHandler(handler);
    defer setTestNativeHttpHandler(null);

    const response = try httpPostWithStatusHeadersAndTimeout(
        allocator,
        "https://api.example.test/messages",
        "{}",
        &.{},
        "5",
    );
    defer allocator.free(response.headers);
    defer allocator.free(response.body);

    try std.testing.expectEqual(@as(u16, 201), response.status_code);
    try std.testing.expectEqualStrings("HTTP/1.1 201 Created\r\nx-request-id: req_123", response.headers);
    try std.testing.expectEqualStrings("{\"id\":\"msg_1\"}", response.body);
}

test "native migration preserves preflight interrupt semantics" {
    var interrupted: AtomicBool = .init(true);
    setThreadInterruptFlag(&interrupted);
    defer setThreadInterruptFlag(null);

    const allocator = std.testing.allocator;
    const handler = struct {
        fn handle(_: Allocator, _: NativeHttpRequest) anyerror!NativeHttpResponse {
            return error.TestExpectedEqual;
        }
    }.handle;
    setTestNativeHttpHandler(handler);
    defer setTestNativeHttpHandler(null);

    try std.testing.expectError(
        error.HttpInterrupted,
        httpGetMaxBytes(allocator, "https://api.example.test/interrupt", &.{}, "3", 4),
    );
}

test "native migration preserves form post and zero timeout semantics" {
    const allocator = std.testing.allocator;
    const handler = struct {
        fn handle(alloc: Allocator, request: NativeHttpRequest) anyerror!NativeHttpResponse {
            try std.testing.expectEqual(std.http.Method.POST, request.method);
            try std.testing.expectEqualStrings("https://api.example.test/oauth/token", request.url);
            try std.testing.expectEqualStrings("grant_type=client_credentials", request.payload.?);
            try std.testing.expectEqual(@as(?u64, null), request.timeout_secs);
            try std.testing.expectEqual(@as(usize, 1), request.headers.len);
            try std.testing.expectEqualStrings("Content-Type", request.headers[0].name);
            try std.testing.expectEqualStrings("application/x-www-form-urlencoded", request.headers[0].value);
            return .{ .status_code = 200, .body = try alloc.dupe(u8, "token") };
        }
    }.handle;

    setTestNativeHttpHandler(handler);
    defer setTestNativeHttpHandler(null);

    const body = try httpPostFormWithProxy(
        allocator,
        "https://api.example.test/oauth/token",
        "grant_type=client_credentials",
        null,
        "0",
    );
    defer allocator.free(body);

    try std.testing.expectEqualStrings("token", body);
}

test "native migration preserves put helper semantics" {
    const allocator = std.testing.allocator;
    const handler = struct {
        fn handle(alloc: Allocator, request: NativeHttpRequest) anyerror!NativeHttpResponse {
            try std.testing.expectEqual(std.http.Method.PUT, request.method);
            try std.testing.expectEqualStrings("https://api.example.test/messages/1", request.url);
            try std.testing.expectEqualStrings("{\"read\":true}", request.payload.?);
            try std.testing.expect(!request.fail_on_http_error);
            try std.testing.expectEqual(@as(usize, 2), request.headers.len);
            try std.testing.expectEqualStrings("Content-Type", request.headers[0].name);
            try std.testing.expectEqualStrings("application/json", request.headers[0].value);
            try std.testing.expectEqualStrings("If-Match", request.headers[1].name);
            try std.testing.expectEqualStrings("etag-1", request.headers[1].value);
            return .{ .status_code = 204, .body = try alloc.dupe(u8, "") };
        }
    }.handle;

    setTestNativeHttpHandler(handler);
    defer setTestNativeHttpHandler(null);

    const body = try httpPut(
        allocator,
        "https://api.example.test/messages/1",
        "{\"read\":true}",
        &.{"If-Match: etag-1"},
    );
    defer allocator.free(body);

    try std.testing.expectEqualStrings("", body);
}

test "native migration preserves sse get helper semantics" {
    const allocator = std.testing.allocator;
    const handler = struct {
        fn handle(alloc: Allocator, request: NativeHttpRequest) anyerror!NativeHttpResponse {
            try std.testing.expectEqual(std.http.Method.GET, request.method);
            try std.testing.expectEqualStrings("https://api.example.test/events", request.url);
            try std.testing.expect(request.fail_on_http_error);
            try std.testing.expectEqual(@as(?u64, 12), request.timeout_secs);
            try std.testing.expectEqual(@as(usize, 1), request.headers.len);
            try std.testing.expectEqualStrings("Accept", request.headers[0].name);
            try std.testing.expectEqualStrings("text/event-stream", request.headers[0].value);
            return .{ .status_code = 200, .body = try alloc.dupe(u8, "data: ok\n\n") };
        }
    }.handle;

    setTestNativeHttpHandler(handler);
    defer setTestNativeHttpHandler(null);

    const body = try httpGetSse(allocator, "https://api.example.test/events", "12");
    defer allocator.free(body);

    try std.testing.expectEqualStrings("data: ok\n\n", body);
}

test "native migration converts request timeout to socket timeval" {
    const tv = socketTimeoutForSeconds(2);
    try std.testing.expectEqual(@as(@TypeOf(tv.sec), 2), tv.sec);
    try std.testing.expectEqual(@as(@TypeOf(tv.usec), 0), tv.usec);
}

test "native migration preloads TLS before pinned https connect" {
    const https_uri = try std.Uri.parse("https://api.example.test/v1/messages");
    const http_uri = try std.Uri.parse("http://api.example.test/v1/messages");

    // Regression: pinned HTTPS connections are opened manually to preserve
    // SNI while connecting to a resolved IP. That path must load the system CA
    // bundle before std.http creates the TLS client.
    try std.testing.expect(shouldPreloadTlsForPinnedResolve(https_uri, "api.example.test:443:203.0.113.10", null));
    try std.testing.expect(!shouldPreloadTlsForPinnedResolve(http_uri, "api.example.test:80:203.0.113.10", null));
    try std.testing.expect(!shouldPreloadTlsForPinnedResolve(https_uri, null, null));
    try std.testing.expect(!shouldPreloadTlsForPinnedResolve(https_uri, "api.example.test:443:203.0.113.10", "http://proxy.example.test:8080"));
}

test "buildSafeResolveEntryForRemoteUrl allows explicit local host without pinning" {
    try std.testing.expect((try buildSafeResolveEntryForRemoteUrl(std.testing.allocator, "http://127.0.0.1:11434/api/chat")) == null);
}

test "buildSafeResolveEntryForRemoteUrl rejects loopback integer alias" {
    try std.testing.expectError(error.LocalAddressBlocked, buildSafeResolveEntryForRemoteUrl(std.testing.allocator, "https://2130706433/v1"));
}

test "buildSafeResolveEntryForRemoteUrl rejects malformed URL" {
    try std.testing.expectError(error.InvalidUrl, buildSafeResolveEntryForRemoteUrl(std.testing.allocator, "notaurl"));
}

test "http post max bytes is increased for large provider responses" {
    try std.testing.expect(DEFAULT_HTTP_POST_MAX_BYTES >= 8 * 1024 * 1024);
}

test "normalizeProxyEnvValue trims surrounding whitespace" {
    const alloc = std.testing.allocator;
    const normalized = try normalizeProxyEnvValue(alloc, "  socks5://127.0.0.1:1080 \r\n");
    defer if (normalized) |v| alloc.free(v);
    try std.testing.expect(normalized != null);
    try std.testing.expectEqualStrings("socks5://127.0.0.1:1080", normalized.?);
}

test "normalizeProxyEnvValue rejects empty values" {
    const normalized = try normalizeProxyEnvValue(std.testing.allocator, " \t\r\n");
    try std.testing.expect(normalized == null);
}

test "setProxyOverride applies and clears process-wide override" {
    const override = "  socks5://proxy-override-test.invalid:1080  ";
    const normalized_override = "socks5://proxy-override-test.invalid:1080";

    try setProxyOverride(override);
    const from_override = try getProxyFromEnv(std.testing.allocator);
    defer if (from_override) |v| std.testing.allocator.free(v);
    try std.testing.expect(from_override != null);
    try std.testing.expectEqualStrings(normalized_override, from_override.?);

    try setProxyOverride(null);
    const after_clear = try getProxyFromEnv(std.testing.allocator);
    defer if (after_clear) |v| std.testing.allocator.free(v);
    if (after_clear) |proxy| {
        // Environment may define a proxy; only assert our override no longer leaks.
        try std.testing.expect(!std.mem.eql(u8, proxy, normalized_override));
    }
}

test "setProxyOverride accepts long proxy URLs" {
    const allocator = std.testing.allocator;
    var long_proxy = try allocator.alloc(u8, 1600);
    defer allocator.free(long_proxy);

    @memcpy(long_proxy[0.."http://".len], "http://");
    @memset(long_proxy["http://".len..], 'a');

    try setProxyOverride(long_proxy);
    defer setProxyOverride(null) catch unreachable;

    const from_override = try getProxyFromEnv(allocator);
    defer if (from_override) |v| allocator.free(v);
    try std.testing.expect(from_override != null);
    try std.testing.expectEqual(long_proxy.len, from_override.?.len);
}

test "getProxyFromEnvMap honors lowercase https_proxy before http_proxy" {
    var env_map = std_compat.process.EnvMap.init(std.testing.allocator);
    defer env_map.deinit();

    try env_map.put("http_proxy", "http://http-only.example:8080");
    try env_map.put("https_proxy", "https://secure.example:8443");

    const proxy = try getProxyFromEnvMap(std.testing.allocator, &env_map, &https_proxy_env_var_names);
    defer if (proxy) |value| std.testing.allocator.free(value);

    try std.testing.expect(proxy != null);
    try std.testing.expectEqualStrings("https://secure.example:8443", proxy.?);
}

test "applyProxyOverrideToEnvMap overwrites existing proxy values" {
    var env_map = std_compat.process.EnvMap.init(std.testing.allocator);
    defer env_map.deinit();

    try env_map.put("HTTPS_PROXY", "https://old.example:9443");
    try setProxyOverride("  socks5://override.example:1080  ");
    defer setProxyOverride(null) catch unreachable;

    try std.testing.expect(try applyProxyOverrideToEnvMap(&env_map));
    try std.testing.expectEqualStrings("socks5://override.example:1080", env_map.get("HTTPS_PROXY").?);
    try std.testing.expectEqualStrings("socks5://override.example:1080", env_map.get("http_proxy").?);
}

test "initClientDefaultProxiesFromEnvMap parses proxy settings" {
    var env_map = std_compat.process.EnvMap.init(std.testing.allocator);
    defer env_map.deinit();

    try env_map.put("http_proxy", "http://proxy-http.example:8080");
    try env_map.put("HTTPS_PROXY", "https://proxy-https.example:8443");

    var proxy_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer proxy_arena.deinit();

    var client: std.http.Client = .{ .allocator = std.testing.allocator, .io = std.testing.io };
    defer client.deinit();

    // Regression: Zig 0.16 requires an explicit environ map for initDefaultProxies.
    try initClientDefaultProxiesFromEnvMap(&client, proxy_arena.allocator(), &env_map);

    try std.testing.expect(client.http_proxy != null);
    try std.testing.expect(client.https_proxy != null);
    try std.testing.expectEqual(@as(u16, 8080), client.http_proxy.?.port);
    try std.testing.expectEqual(@as(u16, 8443), client.https_proxy.?.port);
    try std.testing.expect(client.http_proxy.?.host.eql(try std.Io.net.HostName.init("proxy-http.example")));
    try std.testing.expect(client.https_proxy.?.host.eql(try std.Io.net.HostName.init("proxy-https.example")));
}

test "native migration rejects socks proxy from default proxy env map" {
    var env_map = std_compat.process.EnvMap.init(std.testing.allocator);
    defer env_map.deinit();

    try env_map.put("ALL_PROXY", "socks5://127.0.0.1:1080");

    var proxy_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer proxy_arena.deinit();

    var client: std.http.Client = .{ .allocator = std.testing.allocator, .io = std.testing.io };
    defer client.deinit();

    // Regression: std.http silently ignores unsupported proxy schemes. The
    // migration must fail closed so configured SOCKS traffic is not sent direct.
    try std.testing.expectError(
        error.UnsupportedProxyScheme,
        initClientDefaultProxiesFromEnvMap(&client, proxy_arena.allocator(), &env_map),
    );
}

test "native migration rejects socks proxy instead of bypassing it" {
    // Regression: the previous subprocess HTTP path honored socks5:// proxies.
    // std.http in Zig 0.16 only
    // supports HTTP/HTTPS proxies, so native migration must fail closed instead
    // of silently sending traffic without the configured proxy.
    var client = initClientWithOptionalProxy(std.testing.allocator, "socks5://127.0.0.1:1080") catch |err| {
        try std.testing.expectEqual(error.UnsupportedProxyScheme, err);
        return;
    };
    defer client.deinit();
    return error.TestExpectedError;
}

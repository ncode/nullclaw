const std = @import("std");
const config_types = @import("config_types.zig");
const health = @import("health.zig");

pub const ChannelAccountSummary = struct {
    type: []const u8,
    account_id: []const u8,
    configured: bool = true,
    status: []const u8,
};

pub const ChannelAccountDetail = struct {
    account_id: []const u8,
    configured: bool = true,
};

pub const ChannelTypeDetail = struct {
    type: []const u8,
    status: []const u8,
    accounts: []const ChannelAccountDetail,

    pub fn deinit(self: *ChannelTypeDetail, allocator: std.mem.Allocator) void {
        if (self.accounts.len > 0) allocator.free(self.accounts);
        self.* = undefined;
    }
};

const ChannelTypeEntry = struct {
    field: []const u8,
    type_name: []const u8,
};

pub const channel_types = [_]ChannelTypeEntry{
    .{ .field = "telegram", .type_name = "telegram" },
    .{ .field = "discord", .type_name = "discord" },
    .{ .field = "slack", .type_name = "slack" },
    .{ .field = "imessage", .type_name = "imessage" },
    .{ .field = "matrix", .type_name = "matrix" },
    .{ .field = "mattermost", .type_name = "mattermost" },
    .{ .field = "whatsapp", .type_name = "whatsapp" },
    .{ .field = "teams", .type_name = "teams" },
    .{ .field = "irc", .type_name = "irc" },
    .{ .field = "lark", .type_name = "lark" },
    .{ .field = "dingtalk", .type_name = "dingtalk" },
    .{ .field = "wechat", .type_name = "wechat" },
    .{ .field = "wecom", .type_name = "wecom" },
    .{ .field = "signal", .type_name = "signal" },
    .{ .field = "email", .type_name = "email" },
    .{ .field = "line", .type_name = "line" },
    .{ .field = "qq", .type_name = "qq" },
    .{ .field = "onebot", .type_name = "onebot" },
    .{ .field = "maixcam", .type_name = "maixcam" },
    .{ .field = "web", .type_name = "web" },
    .{ .field = "max", .type_name = "max" },
    .{ .field = "external", .type_name = "external" },
};

pub fn isKnownType(type_name: []const u8) bool {
    inline for (channel_types) |entry| {
        if (std.mem.eql(u8, entry.type_name, type_name)) return true;
    }
    return false;
}

pub fn collectConfiguredChannels(
    allocator: std.mem.Allocator,
    channels: *const config_types.ChannelsConfig,
    snapshot: health.HealthSnapshot,
) ![]ChannelAccountSummary {
    var items = std.ArrayList(ChannelAccountSummary).empty;
    errdefer items.deinit(allocator);

    inline for (channel_types) |entry| {
        try appendChannelAccounts(allocator, &items, @field(channels, entry.field), entry.type_name, snapshot);
    }

    return try items.toOwnedSlice(allocator);
}

pub fn readChannelTypeDetail(
    allocator: std.mem.Allocator,
    channels: *const config_types.ChannelsConfig,
    snapshot: health.HealthSnapshot,
    type_name: []const u8,
) !?ChannelTypeDetail {
    inline for (channel_types) |entry| {
        if (std.mem.eql(u8, entry.type_name, type_name)) {
            var accounts = std.ArrayList(ChannelAccountDetail).empty;
            errdefer accounts.deinit(allocator);

            const slice = @field(channels, entry.field);
            for (slice) |item| {
                try accounts.append(allocator, .{
                    .account_id = accountId(item),
                });
            }

            return .{
                .type = entry.type_name,
                .status = healthStatus(snapshot, entry.type_name),
                .accounts = try accounts.toOwnedSlice(allocator),
            };
        }
    }

    return null;
}

pub fn collectConfiguredChannelsFromRuntimeStatusJson(
    allocator: std.mem.Allocator,
    channels: *const config_types.ChannelsConfig,
    runtime_status_json: []const u8,
) ![]ChannelAccountSummary {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, runtime_status_json, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();

    var items = std.ArrayList(ChannelAccountSummary).empty;
    errdefer items.deinit(allocator);

    inline for (channel_types) |entry| {
        try appendChannelAccountsFromRuntimeStatusJson(allocator, &items, @field(channels, entry.field), entry.type_name, parsed.value);
    }

    return try items.toOwnedSlice(allocator);
}

pub fn readChannelTypeDetailFromRuntimeStatusJson(
    allocator: std.mem.Allocator,
    channels: *const config_types.ChannelsConfig,
    runtime_status_json: []const u8,
    type_name: []const u8,
) !?ChannelTypeDetail {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, runtime_status_json, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();

    inline for (channel_types) |entry| {
        if (std.mem.eql(u8, entry.type_name, type_name)) {
            var accounts = std.ArrayList(ChannelAccountDetail).empty;
            errdefer accounts.deinit(allocator);

            const slice = @field(channels, entry.field);
            for (slice) |item| {
                try accounts.append(allocator, .{
                    .account_id = accountId(item),
                });
            }

            return .{
                .type = entry.type_name,
                .status = runtimeHealthStatus(parsed.value, entry.type_name),
                .accounts = try accounts.toOwnedSlice(allocator),
            };
        }
    }

    return null;
}

fn appendChannelAccounts(
    allocator: std.mem.Allocator,
    items: *std.ArrayList(ChannelAccountSummary),
    slice: anytype,
    type_name: []const u8,
    snapshot: health.HealthSnapshot,
) !void {
    for (slice) |item| {
        try items.append(allocator, .{
            .type = type_name,
            .account_id = accountId(item),
            .status = healthStatus(snapshot, type_name),
        });
    }
}

fn appendChannelAccountsFromRuntimeStatusJson(
    allocator: std.mem.Allocator,
    items: *std.ArrayList(ChannelAccountSummary),
    slice: anytype,
    type_name: []const u8,
    root: std.json.Value,
) !void {
    for (slice) |item| {
        try items.append(allocator, .{
            .type = type_name,
            .account_id = accountId(item),
            .status = runtimeHealthStatus(root, type_name),
        });
    }
}

fn accountId(item: anytype) []const u8 {
    if (comptime @hasField(@TypeOf(item), "account_id")) {
        return item.account_id;
    }
    return "default";
}

fn healthStatus(snapshot: health.HealthSnapshot, type_name: []const u8) []const u8 {
    for (snapshot.components) |entry| {
        if (std.mem.eql(u8, entry.name, type_name)) return entry.health.status;
    }
    return "unknown";
}

fn canonicalStatus(status: []const u8) []const u8 {
    if (std.mem.eql(u8, status, "ok")) return "ok";
    if (std.mem.eql(u8, status, "error")) return "error";
    if (std.mem.eql(u8, status, "starting")) return "starting";
    if (std.mem.eql(u8, status, "idle")) return "idle";
    if (std.mem.eql(u8, status, "stopping")) return "stopping";
    if (std.mem.eql(u8, status, "degraded")) return "degraded";
    if (std.mem.eql(u8, status, "unavailable")) return "unavailable";
    if (std.mem.eql(u8, status, "unauthorized")) return "unauthorized";
    if (std.mem.eql(u8, status, "gateway_error")) return "gateway_error";
    return "unknown";
}

fn runtimeHealthStatus(root: std.json.Value, type_name: []const u8) []const u8 {
    if (root != .object) return "unknown";
    const components = root.object.get("components") orelse return "unknown";
    if (components != .object) return "unknown";
    const component = components.object.get(type_name) orelse return "unknown";
    if (component != .object) return "unknown";
    const status = component.object.get("status") orelse return "unknown";
    return if (status == .string and status.string.len > 0) canonicalStatus(status.string) else "unknown";
}

test "collectConfiguredChannels reports configured accounts and health by type" {
    const allocator = std.testing.allocator;
    const telegram_accounts = [_]config_types.TelegramConfig{
        .{ .account_id = "main", .bot_token = "tok-main" },
        .{ .account_id = "backup", .bot_token = "tok-backup" },
    };
    const discord_accounts = [_]config_types.DiscordConfig{
        .{ .account_id = "guild-a", .token = "disc-token" },
    };
    const channels = config_types.ChannelsConfig{
        .telegram = &telegram_accounts,
        .discord = &discord_accounts,
    };

    health.reset();
    health.markComponentOk("telegram");
    health.markComponentError("discord", "gateway down");

    const snapshot = try health.snapshot(allocator);
    defer snapshot.deinit(allocator);

    const items = try collectConfiguredChannels(allocator, &channels, snapshot);
    defer allocator.free(items);

    try std.testing.expectEqual(@as(usize, 3), items.len);
    try std.testing.expectEqualStrings("telegram", items[0].type);
    try std.testing.expectEqualStrings("main", items[0].account_id);
    try std.testing.expectEqualStrings("ok", items[0].status);
    try std.testing.expectEqualStrings("backup", items[1].account_id);
    try std.testing.expectEqualStrings("discord", items[2].type);
    try std.testing.expectEqualStrings("error", items[2].status);
}

test "readChannelTypeDetail returns empty accounts for known unconfigured type" {
    const allocator = std.testing.allocator;
    const channels = config_types.ChannelsConfig{};

    health.reset();
    const snapshot = try health.snapshot(allocator);
    defer snapshot.deinit(allocator);

    var detail = (try readChannelTypeDetail(allocator, &channels, snapshot, "discord")).?;
    defer detail.deinit(allocator);

    try std.testing.expectEqualStrings("discord", detail.type);
    try std.testing.expectEqualStrings("unknown", detail.status);
    try std.testing.expectEqual(@as(usize, 0), detail.accounts.len);
}

test "readChannelTypeDetail returns null for unknown type" {
    const allocator = std.testing.allocator;
    const channels = config_types.ChannelsConfig{};

    health.reset();
    const snapshot = try health.snapshot(allocator);
    defer snapshot.deinit(allocator);

    try std.testing.expect((try readChannelTypeDetail(allocator, &channels, snapshot, "nonexistent")) == null);
}

test "collectConfiguredChannelsFromRuntimeStatusJson uses live component statuses" {
    const allocator = std.testing.allocator;
    const telegram_accounts = [_]config_types.TelegramConfig{
        .{ .account_id = "main", .bot_token = "tok-main" },
    };
    const discord_accounts = [_]config_types.DiscordConfig{
        .{ .account_id = "guild-a", .token = "disc-token" },
    };
    const channels = config_types.ChannelsConfig{
        .telegram = &telegram_accounts,
        .discord = &discord_accounts,
    };

    const runtime_status_json =
        \\{"version":"1.0.0","pid":1234,"uptime_seconds":42,"overall_status":"starting","components":{"telegram":{"status":"ok"},"discord":{"status":"error"}}}
    ;

    const items = try collectConfiguredChannelsFromRuntimeStatusJson(allocator, &channels, runtime_status_json);
    defer allocator.free(items);

    try std.testing.expectEqual(@as(usize, 2), items.len);
    try std.testing.expectEqualStrings("ok", items[0].status);
    try std.testing.expectEqualStrings("error", items[1].status);
}

test "readChannelTypeDetailFromRuntimeStatusJson uses live component status" {
    const allocator = std.testing.allocator;
    const telegram_accounts = [_]config_types.TelegramConfig{
        .{ .account_id = "main", .bot_token = "tok-main" },
    };
    const channels = config_types.ChannelsConfig{
        .telegram = &telegram_accounts,
    };

    const runtime_status_json =
        \\{"version":"1.0.0","pid":1234,"uptime_seconds":42,"overall_status":"ok","components":{"telegram":{"status":"ok"}}}
    ;

    var detail = (try readChannelTypeDetailFromRuntimeStatusJson(allocator, &channels, runtime_status_json, "telegram")).?;
    defer detail.deinit(allocator);

    try std.testing.expectEqualStrings("telegram", detail.type);
    try std.testing.expectEqualStrings("ok", detail.status);
    try std.testing.expectEqual(@as(usize, 1), detail.accounts.len);
    try std.testing.expectEqualStrings("main", detail.accounts[0].account_id);
}

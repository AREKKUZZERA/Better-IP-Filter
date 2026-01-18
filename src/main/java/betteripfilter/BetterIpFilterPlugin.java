package betteripfilter;

import betteripfilter.command.IpfCommand;
import betteripfilter.command.IpfTabCompleter;
import betteripfilter.listener.IpFilterListener;
import org.bukkit.ChatColor;
import org.bukkit.command.PluginCommand;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

public class BetterIpFilterPlugin extends JavaPlugin {
    private static final int RATE_LIMIT_CLEANUP_THRESHOLD = 5000;

    private IpStore ipStore;
    private RateLimiter rateLimiter;
    private WebhookNotifier webhookNotifier;

    private boolean rateLimitEnabled;
    private long rateLimitWindowMillis;
    private int rateLimitMaxAttempts;
    private String rateLimitMessage;

    private boolean failsafeDenyAll;
    private String failsafeMessage;

    private boolean logDenied;
    private boolean logDeniedToFile;
    private String deniedLogFileName;

    private boolean webhookEnabled;
    private String webhookUrl;
    private boolean webhookOnDenied;
    private boolean webhookOnRateLimit;
    private boolean webhookOnFailsafe;
    private int webhookTimeoutMs;

    private String proxyMode;
    private Set<String> trustedForwardedIps;

    @Override
    public void onEnable() {
        saveDefaultConfig();
        loadSettings();

        ipStore = new IpStore(this);
        ipStore.load();
        if (!ipStore.isAvailable()) {
            getLogger().warning("Whitelist unavailable: " + ipStore.getLastError());
        }

        getServer().getPluginManager().registerEvents(new IpFilterListener(this, ipStore), this);

        PluginCommand command = getCommand("ipf");
        if (command != null) {
            IpfCommand executor = new IpfCommand(this, ipStore);
            command.setExecutor(executor);
            command.setTabCompleter(new IpfTabCompleter(ipStore));
        } else {
            getLogger().severe("Command 'ipf' not found in plugin.yml");
        }
    }

    private void loadSettings() {
        rateLimitEnabled = getConfig().getBoolean("ratelimit.enabled", true);
        int windowSeconds = Math.max(1, getConfig().getInt("ratelimit.window-seconds", 10));
        rateLimitWindowMillis = windowSeconds * 1000L;
        rateLimitMaxAttempts = Math.max(1, getConfig().getInt("ratelimit.max-attempts", 5));
        rateLimitMessage = getConfig().getString("ratelimit.message", "&cToo many connection attempts. Try again later.");

        String failsafeMode = getConfig().getString("failsafe.mode", "DENY_ALL").toUpperCase(Locale.ROOT);
        failsafeDenyAll = "DENY_ALL".equals(failsafeMode);
        failsafeMessage = getConfig().getString("failsafe.message", "&cWhitelist unavailable. Try again later.");

        logDenied = getConfig().getBoolean("logging.denied", true);
        logDeniedToFile = getConfig().getBoolean("logging.denied-to-file", true);
        deniedLogFileName = getConfig().getString("logging.file-name", "denied.log");

        webhookEnabled = getConfig().getBoolean("webhook.enabled", false);
        webhookUrl = getConfig().getString("webhook.url", "");
        webhookOnDenied = getConfig().getBoolean("webhook.on-denied", true);
        webhookOnRateLimit = getConfig().getBoolean("webhook.on-ratelimit", true);
        webhookOnFailsafe = getConfig().getBoolean("webhook.on-failsafe", true);
        webhookTimeoutMs = Math.max(500, getConfig().getInt("webhook.timeout-ms", 3000));

        proxyMode = getConfig().getString("proxy.mode", "DIRECT").toUpperCase(Locale.ROOT);
        trustedForwardedIps = new HashSet<>(getConfig().getStringList("proxy.trusted-forwarded-ips"));

        rateLimiter = new RateLimiter(RATE_LIMIT_CLEANUP_THRESHOLD);
        webhookNotifier = new WebhookNotifier(getLogger());
    }

    public boolean isFilteringEnabled() {
        return getConfig().getBoolean("enabled", true);
    }

    public void setFilteringEnabled(boolean enabled) {
        getConfig().set("enabled", enabled);
        saveConfig();
    }

    public String resolveClientIp(AsyncPlayerPreLoginEvent event) {
        String remoteIp = event.getAddress().getHostAddress();
        if (!"DIRECT".equals(proxyMode)) {
            if (!trustedForwardedIps.isEmpty() && trustedForwardedIps.contains(remoteIp)) {
                return remoteIp;
            }
            return remoteIp;
        }
        return remoteIp;
    }

    public boolean isRateLimitEnabled() {
        return rateLimitEnabled;
    }

    public long getRateLimitWindowMillis() {
        return rateLimitWindowMillis;
    }

    public int getRateLimitMaxAttempts() {
        return rateLimitMaxAttempts;
    }

    public String getRateLimitMessage() {
        return rateLimitMessage;
    }

    public boolean isFailsafeDenyAll() {
        return failsafeDenyAll;
    }

    public String getFailsafeMessage() {
        return failsafeMessage;
    }

    public RateLimiter getRateLimiter() {
        return rateLimiter;
    }

    public void handleDenied(DenyReason reason, String name, String ip) {
        if (logDenied) {
            String line = formatDeniedLine(reason, name, ip);
            getLogger().info(line);
            if (logDeniedToFile) {
                appendDeniedLine(line);
            }
        } else if (logDeniedToFile) {
            appendDeniedLine(formatDeniedLine(reason, name, ip));
        }

        if (shouldSendWebhook(reason)) {
            webhookNotifier.send(webhookUrl, webhookTimeoutMs, reason, name, ip);
        }
    }

    private boolean shouldSendWebhook(DenyReason reason) {
        if (!webhookEnabled || webhookUrl == null || webhookUrl.isBlank()) {
            return false;
        }
        return switch (reason) {
            case NOT_WHITELISTED -> webhookOnDenied;
            case RATE_LIMIT -> webhookOnRateLimit;
            case FAILSAFE -> webhookOnFailsafe;
        };
    }

    private String formatDeniedLine(DenyReason reason, String name, String ip) {
        String safeName = name == null || name.isBlank() ? "-" : name;
        String safeIp = ip == null || ip.isBlank() ? "-" : ip;
        return Instant.now().toString() + " " + reason.name() + " " + safeName + " " + safeIp;
    }

    private void appendDeniedLine(String line) {
        if (!getDataFolder().exists() && !getDataFolder().mkdirs()) {
            getLogger().warning("Failed to create plugin data folder for denied log.");
            return;
        }
        File logFile = new File(getDataFolder(), deniedLogFileName);
        try (BufferedWriter writer = Files.newBufferedWriter(logFile.toPath(),
            StandardOpenOption.CREATE, StandardOpenOption.APPEND)) {
            writer.write(line);
            writer.newLine();
        } catch (IOException e) {
            getLogger().warning("Failed to write denied log: " + e.getMessage());
        }
    }

    @SuppressWarnings("deprecation")
    public String color(String message) {
        return ChatColor.translateAlternateColorCodes('&', message);
    }

    public String msg(String key) {
        return getConfig().getString("messages." + key, "");
    }

    public String prefixed(String message) {
        return color(msg("prefix") + message);
    }
}

package betteripfilter;

import betteripfilter.command.IpfCommand;
import betteripfilter.command.IpfTabCompleter;
import betteripfilter.listener.IpFilterListener;
import org.bukkit.ChatColor;
import org.bukkit.command.PluginCommand;
import org.bukkit.plugin.java.JavaPlugin;

import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

public class BetterIpFilterPlugin extends JavaPlugin {
    private static final int RATE_LIMIT_CLEANUP_THRESHOLD = 5000;

    private IpStore ipStore;
    private RateLimiter rateLimiter;
    private WebhookNotifier webhookNotifier;
    private AsyncDeniedLogWriter deniedLogWriter;

    private boolean rateLimitEnabled;
    private long rateLimitWindowMillis;
    private int rateLimitMaxAttempts;
    private String rateLimitMessage;

    private boolean failsafeDenyAll;
    private String failsafeMessage;

    private boolean logDenied;
    private boolean logDeniedToFile;
    private String deniedLogFileName;
    private int deniedLogQueueSize;
    private int deniedLogBatchSize;
    private long deniedLogFlushIntervalMs;
    private int deniedLogDropNoticeSeconds;

    private boolean webhookEnabled;
    private String webhookUrl;
    private boolean webhookOnDenied;
    private boolean webhookOnRateLimit;
    private boolean webhookOnFailsafe;
    private int webhookTimeoutMs;
    private int webhookMaxPerSecond;
    private int webhookQueueSize;

    private String proxyMode;
    private Set<Integer> trustedForwardedIps;

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

    @Override
    public void onDisable() {
        if (deniedLogWriter != null) {
            deniedLogWriter.shutdown(2000);
            deniedLogWriter = null;
        }
        if (webhookNotifier != null) {
            webhookNotifier.shutdown(2000);
            webhookNotifier = null;
        }
    }

    public void loadSettings() {
        rateLimitEnabled = getConfig().getBoolean("ratelimit.enabled", true);
        int windowSeconds = Math.max(1, getConfig().getInt("ratelimit.window-seconds", 10));
        rateLimitWindowMillis = windowSeconds * 1000L;
        rateLimitMaxAttempts = Math.max(1, getConfig().getInt("ratelimit.max-attempts", 5));
        rateLimitMessage = getConfig().getString("ratelimit.message",
                "&cToo many connection attempts. Try again later.");

        String failsafeMode = getConfig().getString("failsafe.mode", "DENY_ALL").toUpperCase(Locale.ROOT);
        failsafeDenyAll = "DENY_ALL".equals(failsafeMode);
        failsafeMessage = getConfig().getString("failsafe.message", "&cWhitelist unavailable. Try again later.");

        logDenied = getConfig().getBoolean("logging.denied", true);
        logDeniedToFile = getConfig().getBoolean("logging.denied-to-file", true);
        deniedLogFileName = getConfig().getString("logging.file-name", "denied.log");
        deniedLogQueueSize = Math.max(100, getConfig().getInt("logging.async-queue-size", 8192));
        deniedLogBatchSize = Math.max(1, getConfig().getInt("logging.async-batch-size", 64));
        deniedLogFlushIntervalMs = Math.max(100, getConfig().getLong("logging.async-flush-interval-ms", 1000));
        deniedLogDropNoticeSeconds = Math.max(1, getConfig().getInt("logging.async-drop-log-interval-seconds", 10));

        webhookEnabled = getConfig().getBoolean("webhook.enabled", false);
        webhookUrl = getConfig().getString("webhook.url", "");
        webhookOnDenied = getConfig().getBoolean("webhook.on-denied", true);
        webhookOnRateLimit = getConfig().getBoolean("webhook.on-ratelimit", true);
        webhookOnFailsafe = getConfig().getBoolean("webhook.on-failsafe", true);
        webhookTimeoutMs = Math.max(500, getConfig().getInt("webhook.timeout-ms", 3000));
        webhookMaxPerSecond = Math.max(1, getConfig().getInt("webhook.max-per-second", 5));
        webhookQueueSize = Math.max(10, getConfig().getInt("webhook.max-queue-size", 1000));

        proxyMode = getConfig().getString("proxy.mode", "DIRECT").toUpperCase(Locale.ROOT);
        trustedForwardedIps = new HashSet<>();
        for (String entry : getConfig().getStringList("proxy.trusted-forwarded-ips")) {
            int ipInt = Ipv4.parseToInt(entry);
            if (ipInt != Ipv4.INVALID) {
                trustedForwardedIps.add(ipInt);
            }
        }

        rateLimiter = new RateLimiter(RATE_LIMIT_CLEANUP_THRESHOLD);
        if (deniedLogWriter != null) {
            deniedLogWriter.shutdown(1000);
        }
        if (logDeniedToFile) {
            deniedLogWriter = new AsyncDeniedLogWriter(
                    getLogger(),
                    Path.of(getDataFolder().getPath(), deniedLogFileName),
                    deniedLogQueueSize,
                    deniedLogBatchSize,
                    deniedLogFlushIntervalMs,
                    Duration.ofSeconds(deniedLogDropNoticeSeconds)
            );
        } else {
            deniedLogWriter = null;
        }
        if (webhookNotifier != null) {
            webhookNotifier.shutdown(1000);
        }
        webhookNotifier = new WebhookNotifier(getLogger(), webhookQueueSize, webhookMaxPerSecond, 10_000);
    }

    public boolean isFilteringEnabled() {
        return getConfig().getBoolean("enabled", true);
    }

    public void setFilteringEnabled(boolean enabled) {
        getConfig().set("enabled", enabled);
        saveConfig();
    }

    public boolean isProxyGateEnabled() {
        return "PROXY_GATE".equals(proxyMode);
    }

    public boolean hasTrustedForwardedIps() {
        return !trustedForwardedIps.isEmpty();
    }

    public boolean isTrustedProxy(int ipInt) {
        return trustedForwardedIps.contains(ipInt);
    }

    public String getProxyMode() {
        return proxyMode;
    }

    public int getTrustedForwardedIpsCount() {
        return trustedForwardedIps.size();
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

    public String getFailsafeMode() {
        return failsafeDenyAll ? "DENY_ALL" : "ALLOW_ALL";
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

    public boolean isWebhookEnabled() {
        return webhookEnabled;
    }

    public boolean isWebhookConfigured() {
        return webhookEnabled && webhookUrl != null && !webhookUrl.isBlank();
    }

    public void handleDenied(DenyReason reason, String name, String ip) {
        if (logDenied) {
            String line = formatDeniedLine(reason, name, ip);
            getLogger().info(line);
            if (logDeniedToFile && deniedLogWriter != null) {
                deniedLogWriter.enqueue(line);
            }
        } else if (logDeniedToFile && deniedLogWriter != null) {
            deniedLogWriter.enqueue(formatDeniedLine(reason, name, ip));
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
            case PROXY_NOT_TRUSTED -> webhookOnDenied;
        };
    }

    private String formatDeniedLine(DenyReason reason, String name, String ip) {
        String safeName = name == null || name.isBlank() ? "-" : name;
        String safeIp = ip == null || ip.isBlank() ? "-" : ip;
        return Instant.now().toString() + " " + reason.name() + " " + safeName + " " + safeIp;
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

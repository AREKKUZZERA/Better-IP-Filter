package betteripfilter;

import betteripfilter.command.IpfCommand;
import betteripfilter.command.IpfTabCompleter;
import betteripfilter.listener.IpFilterListener;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;
import org.bukkit.command.PluginCommand;
import org.bukkit.plugin.java.JavaPlugin;

import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.Locale;
import java.util.OptionalInt;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

public class BetterIpFilterPlugin extends JavaPlugin {
    private static final int RATE_LIMIT_CLEANUP_THRESHOLD = 5000;
    private static final String DEFAULT_DENIED_LOG_FILE = "denied.log";

    private IpStore ipStore;
    private RateLimiter rateLimiter;
    private WebhookNotifier webhookNotifier;
    private AsyncDeniedLogWriter deniedLogWriter;

    // Settings loaded from config
    private boolean filteringEnabled;

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
    private boolean webhookAllowLocalAddresses;
    private int webhookTimeoutMs;
    private int webhookMaxPerSecond;
    private int webhookQueueSize;

    private String proxyMode;
    private Set<Integer> trustedForwardedIps;
    private final AtomicLong deniedNotWhitelisted = new AtomicLong();
    private final AtomicLong deniedProxyNotTrusted = new AtomicLong();
    private final AtomicLong deniedRateLimit = new AtomicLong();
    private final AtomicLong deniedFailsafe = new AtomicLong();

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
            command.setExecutor(new IpfCommand(this, ipStore));
            command.setTabCompleter(new IpfTabCompleter(ipStore));
        } else {
            getLogger().severe("Command 'ipf' not found in plugin.yml — check plugin.yml");
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
        filteringEnabled     = getConfig().getBoolean("enabled", true);

        rateLimitEnabled     = getConfig().getBoolean("ratelimit.enabled", true);
        int windowSec        = Math.max(1, getConfig().getInt("ratelimit.window-seconds", 10));
        rateLimitWindowMillis = windowSec * 1000L;
        rateLimitMaxAttempts = Math.max(1, getConfig().getInt("ratelimit.max-attempts", 5));
        rateLimitMessage     = getConfig().getString("ratelimit.message",
                "&cToo many connection attempts. Try again later.");

        String failsafeMode = configString("failsafe.mode", "DENY_ALL").toUpperCase(Locale.ROOT);
        failsafeDenyAll = switch (failsafeMode) {
            case "DENY_ALL" -> true;
            case "ALLOW_ALL" -> false;
            default -> {
                getLogger().warning("Unknown failsafe.mode '" + failsafeMode + "', using DENY_ALL.");
                yield true;
            }
        };
        failsafeMessage = getConfig().getString("failsafe.message", "&cWhitelist unavailable. Try again later.");

        logDenied                = getConfig().getBoolean("logging.denied", true);
        logDeniedToFile          = getConfig().getBoolean("logging.denied-to-file", true);
        deniedLogFileName        = safeLogFileName(getConfig().getString("logging.file-name", DEFAULT_DENIED_LOG_FILE));
        deniedLogQueueSize       = Math.max(100, getConfig().getInt("logging.async-queue-size", 8192));
        deniedLogBatchSize       = Math.max(1,   getConfig().getInt("logging.async-batch-size", 64));
        deniedLogFlushIntervalMs = Math.max(100, getConfig().getLong("logging.async-flush-interval-ms", 1000));
        deniedLogDropNoticeSeconds = Math.max(1, getConfig().getInt("logging.async-drop-log-interval-seconds", 10));

        webhookEnabled     = getConfig().getBoolean("webhook.enabled", false);
        String configuredWebhookUrl = getConfig().getString("webhook.url", "");
        webhookUrl         = configuredWebhookUrl == null ? "" : configuredWebhookUrl.trim();
        webhookOnDenied    = getConfig().getBoolean("webhook.on-denied", true);
        webhookOnRateLimit = getConfig().getBoolean("webhook.on-ratelimit", true);
        webhookOnFailsafe  = getConfig().getBoolean("webhook.on-failsafe", true);
        webhookAllowLocalAddresses = getConfig().getBoolean("webhook.allow-local-addresses", false);
        webhookTimeoutMs   = Math.max(500, getConfig().getInt("webhook.timeout-ms", 3000));
        webhookMaxPerSecond = Math.max(1,  getConfig().getInt("webhook.max-per-second", 5));
        webhookQueueSize   = Math.max(10,  getConfig().getInt("webhook.max-queue-size", 1000));

        proxyMode = configString("proxy.mode", "DIRECT").toUpperCase(Locale.ROOT);
        if (!"DIRECT".equals(proxyMode) && !"PROXY_GATE".equals(proxyMode)) {
            getLogger().warning("Unknown proxy.mode '" + proxyMode + "', using DIRECT.");
            proxyMode = "DIRECT";
        }
        trustedForwardedIps = new HashSet<>();
        for (String entry : getConfig().getStringList("proxy.trusted-forwarded-ips")) {
            OptionalInt ip = Ipv4.parse(entry);
            if (ip.isPresent()) {
                trustedForwardedIps.add(ip.getAsInt());
            } else {
                getLogger().warning("Skipping invalid trusted-forwarded-ip: '" + entry + "'");
            }
        }
        if (isProxyGateEnabled() && trustedForwardedIps.isEmpty()) {
            getLogger().warning("proxy.mode is PROXY_GATE, but proxy.trusted-forwarded-ips is empty; all connections will be denied.");
        }

        rateLimiter = new RateLimiter(RATE_LIMIT_CLEANUP_THRESHOLD);

        if (deniedLogWriter != null) deniedLogWriter.shutdown(1000);
        deniedLogWriter = logDeniedToFile
                ? new AsyncDeniedLogWriter(
                        getLogger(),
                        getDataFolder().toPath().resolve(deniedLogFileName),
                        deniedLogQueueSize,
                        deniedLogBatchSize,
                        deniedLogFlushIntervalMs,
                        Duration.ofSeconds(deniedLogDropNoticeSeconds))
                : null;

        if (webhookNotifier != null) webhookNotifier.shutdown(1000);
        webhookNotifier = null;
        if (webhookEnabled) {
            if (WebhookNotifier.isValidWebhookUrl(webhookUrl, webhookAllowLocalAddresses)) {
                webhookNotifier = new WebhookNotifier(
                        getLogger(),
                        webhookQueueSize,
                        webhookMaxPerSecond,
                        10_000,
                        webhookAllowLocalAddresses);
            } else {
                webhookEnabled = false;
                getLogger().warning("Webhook is enabled, but webhook.url is invalid; notifications disabled.");
            }
        }
    }

    private String safeLogFileName(String configured) {
        String value = configured == null ? "" : configured.trim();
        if (value.matches("[A-Za-z0-9._-]{1,80}") && !".".equals(value) && !"..".equals(value)) {
            return value;
        }
        getLogger().warning("Unsafe logging.file-name '" + configured + "', using " + DEFAULT_DENIED_LOG_FILE + ".");
        return DEFAULT_DENIED_LOG_FILE;
    }

    private String configString(String path, String fallback) {
        String value = getConfig().getString(path, fallback);
        if (value == null || value.isBlank()) {
            return fallback;
        }
        return value.trim();
    }

    // -------------------------------------------------------------------------
    // Filtering state
    // -------------------------------------------------------------------------

    public boolean isFilteringEnabled() {
        return filteringEnabled;
    }

    public void setFilteringEnabled(boolean enabled) {
        filteringEnabled = enabled;
        getConfig().set("enabled", enabled);
        saveConfig();
    }

    // -------------------------------------------------------------------------
    // Proxy
    // -------------------------------------------------------------------------

    public boolean isProxyGateEnabled() { return "PROXY_GATE".equals(proxyMode); }
    public boolean isTrustedProxy(int ipInt) { return trustedForwardedIps.contains(ipInt); }
    public String  getProxyMode() { return proxyMode; }
    public int     getTrustedForwardedIpsCount() { return trustedForwardedIps.size(); }

    // -------------------------------------------------------------------------
    // Rate limit
    // -------------------------------------------------------------------------

    public boolean    isRateLimitEnabled()      { return rateLimitEnabled; }
    public long       getRateLimitWindowMillis() { return rateLimitWindowMillis; }
    public int        getRateLimitMaxAttempts()  { return rateLimitMaxAttempts; }
    public String     getRateLimitMessage()      { return rateLimitMessage; }
    public RateLimiter getRateLimiter()          { return rateLimiter; }

    // -------------------------------------------------------------------------
    // Failsafe
    // -------------------------------------------------------------------------

    public boolean isFailsafeDenyAll()  { return failsafeDenyAll; }
    public String  getFailsafeMode()    { return failsafeDenyAll ? "DENY_ALL" : "ALLOW_ALL"; }
    public String  getFailsafeMessage() { return failsafeMessage; }

    // -------------------------------------------------------------------------
    // Webhook
    // -------------------------------------------------------------------------

    public boolean isWebhookEnabled()    { return webhookEnabled; }
    public boolean isWebhookConfigured() { return webhookNotifier != null; }

    // -------------------------------------------------------------------------
    // Deny handling
    // -------------------------------------------------------------------------

    public void handleDenied(DenyReason reason, String name, String ip) {
        incrementDeniedCounter(reason);
        String line = null; // built lazily — avoid formatting when neither sink needs it

        if (logDenied) {
            line = formatDeniedLine(reason, name, ip);
            getLogger().info(line);
        }

        if (logDeniedToFile && deniedLogWriter != null) {
            if (line == null) line = formatDeniedLine(reason, name, ip);
            deniedLogWriter.enqueue(line);
        }

        if (shouldSendWebhook(reason)) {
            webhookNotifier.send(webhookUrl, webhookTimeoutMs, reason, name, ip);
        }
    }

    private boolean shouldSendWebhook(DenyReason reason) {
        if (webhookNotifier == null) return false;
        return switch (reason) {
            case NOT_WHITELISTED, PROXY_NOT_TRUSTED -> webhookOnDenied;
            case RATE_LIMIT -> webhookOnRateLimit;
            case FAILSAFE   -> webhookOnFailsafe;
        };
    }

    private void incrementDeniedCounter(DenyReason reason) {
        switch (reason) {
            case NOT_WHITELISTED -> deniedNotWhitelisted.incrementAndGet();
            case PROXY_NOT_TRUSTED -> deniedProxyNotTrusted.incrementAndGet();
            case RATE_LIMIT -> deniedRateLimit.incrementAndGet();
            case FAILSAFE -> deniedFailsafe.incrementAndGet();
        }
    }

    public long getDeniedNotWhitelistedCount() { return deniedNotWhitelisted.get(); }
    public long getDeniedProxyNotTrustedCount() { return deniedProxyNotTrusted.get(); }
    public long getDeniedRateLimitCount() { return deniedRateLimit.get(); }
    public long getDeniedFailsafeCount() { return deniedFailsafe.get(); }

    private String formatDeniedLine(DenyReason reason, String name, String ip) {
        String safeName = safeLogField(name);
        String safeIp   = safeLogField(ip);
        return Instant.now() + " " + reason.name() + " " + safeName + " " + safeIp;
    }

    private static String safeLogField(String value) {
        if (value == null || value.isBlank()) return "-";
        StringBuilder sb = new StringBuilder(Math.min(value.length(), 80));
        for (int i = 0; i < value.length() && sb.length() < 80; i++) {
            char ch = value.charAt(i);
            sb.append(Character.isISOControl(ch) || Character.isWhitespace(ch) ? '_' : ch);
        }
        return sb.isEmpty() ? "-" : sb.toString();
    }

    // -------------------------------------------------------------------------
    // Text / component helpers
    // -------------------------------------------------------------------------

    /** Translates legacy '&amp;' color codes to a Component. */
    public Component colorComponent(String message) {
        return LegacyComponentSerializer.legacyAmpersand().deserialize(message);
    }

    /** Returns a colored Component with the configured prefix prepended. */
    public Component prefixedComponent(String message) {
        return colorComponent(msg("prefix") + message);
    }

    public String msg(String key) {
        return getConfig().getString("messages." + key, "");
    }

    /** Kept for places that still need a plain string (e.g. disconnect reasons). */
    public String colorString(String message) {
        return LegacyComponentSerializer.legacyAmpersand().serialize(colorComponent(message));
    }
}

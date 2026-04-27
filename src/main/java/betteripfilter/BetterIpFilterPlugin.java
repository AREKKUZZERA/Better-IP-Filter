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

public class BetterIpFilterPlugin extends JavaPlugin {
    private static final int RATE_LIMIT_CLEANUP_THRESHOLD = 5000;

    private IpStore ipStore;
    private RateLimiter rateLimiter;
    private WebhookNotifier webhookNotifier;
    private AsyncDeniedLogWriter deniedLogWriter;

    // Settings loaded from config
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
        rateLimitEnabled     = getConfig().getBoolean("ratelimit.enabled", true);
        int windowSec        = Math.max(1, getConfig().getInt("ratelimit.window-seconds", 10));
        rateLimitWindowMillis = windowSec * 1000L;
        rateLimitMaxAttempts = Math.max(1, getConfig().getInt("ratelimit.max-attempts", 5));
        rateLimitMessage     = getConfig().getString("ratelimit.message",
                "&cToo many connection attempts. Try again later.");

        String failsafeMode = getConfig().getString("failsafe.mode", "DENY_ALL").toUpperCase(Locale.ROOT);
        failsafeDenyAll = "DENY_ALL".equals(failsafeMode);
        failsafeMessage = getConfig().getString("failsafe.message", "&cWhitelist unavailable. Try again later.");

        logDenied                = getConfig().getBoolean("logging.denied", true);
        logDeniedToFile          = getConfig().getBoolean("logging.denied-to-file", true);
        deniedLogFileName        = getConfig().getString("logging.file-name", "denied.log");
        deniedLogQueueSize       = Math.max(100, getConfig().getInt("logging.async-queue-size", 8192));
        deniedLogBatchSize       = Math.max(1,   getConfig().getInt("logging.async-batch-size", 64));
        deniedLogFlushIntervalMs = Math.max(100, getConfig().getLong("logging.async-flush-interval-ms", 1000));
        deniedLogDropNoticeSeconds = Math.max(1, getConfig().getInt("logging.async-drop-log-interval-seconds", 10));

        webhookEnabled     = getConfig().getBoolean("webhook.enabled", false);
        webhookUrl         = getConfig().getString("webhook.url", "");
        webhookOnDenied    = getConfig().getBoolean("webhook.on-denied", true);
        webhookOnRateLimit = getConfig().getBoolean("webhook.on-ratelimit", true);
        webhookOnFailsafe  = getConfig().getBoolean("webhook.on-failsafe", true);
        webhookTimeoutMs   = Math.max(500, getConfig().getInt("webhook.timeout-ms", 3000));
        webhookMaxPerSecond = Math.max(1,  getConfig().getInt("webhook.max-per-second", 5));
        webhookQueueSize   = Math.max(10,  getConfig().getInt("webhook.max-queue-size", 1000));

        proxyMode = getConfig().getString("proxy.mode", "DIRECT").toUpperCase(Locale.ROOT);
        trustedForwardedIps = new HashSet<>();
        for (String entry : getConfig().getStringList("proxy.trusted-forwarded-ips")) {
            OptionalInt ip = Ipv4.parse(entry);
            if (ip.isPresent()) {
                trustedForwardedIps.add(ip.getAsInt());
            } else {
                getLogger().warning("Skipping invalid trusted-forwarded-ip: '" + entry + "'");
            }
        }

        rateLimiter = new RateLimiter(RATE_LIMIT_CLEANUP_THRESHOLD);

        if (deniedLogWriter != null) deniedLogWriter.shutdown(1000);
        deniedLogWriter = logDeniedToFile
                ? new AsyncDeniedLogWriter(
                        getLogger(),
                        Path.of(getDataFolder().getPath(), deniedLogFileName),
                        deniedLogQueueSize,
                        deniedLogBatchSize,
                        deniedLogFlushIntervalMs,
                        Duration.ofSeconds(deniedLogDropNoticeSeconds))
                : null;

        if (webhookNotifier != null) webhookNotifier.shutdown(1000);
        webhookNotifier = new WebhookNotifier(getLogger(), webhookQueueSize, webhookMaxPerSecond, 10_000);
    }

    // -------------------------------------------------------------------------
    // Filtering state
    // -------------------------------------------------------------------------

    public boolean isFilteringEnabled() {
        return getConfig().getBoolean("enabled", true);
    }

    public void setFilteringEnabled(boolean enabled) {
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
    public boolean isWebhookConfigured() { return webhookEnabled && webhookUrl != null && !webhookUrl.isBlank(); }

    // -------------------------------------------------------------------------
    // Deny handling
    // -------------------------------------------------------------------------

    public void handleDenied(DenyReason reason, String name, String ip) {
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
        if (!webhookEnabled || webhookUrl == null || webhookUrl.isBlank()) return false;
        return switch (reason) {
            case NOT_WHITELISTED, PROXY_NOT_TRUSTED -> webhookOnDenied;
            case RATE_LIMIT -> webhookOnRateLimit;
            case FAILSAFE   -> webhookOnFailsafe;
        };
    }

    private String formatDeniedLine(DenyReason reason, String name, String ip) {
        String safeName = (name == null || name.isBlank()) ? "-" : name;
        String safeIp   = (ip   == null || ip.isBlank())   ? "-" : ip;
        return Instant.now() + " " + reason.name() + " " + safeName + " " + safeIp;
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

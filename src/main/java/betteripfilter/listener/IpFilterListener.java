package betteripfilter.listener;

import betteripfilter.BetterIpFilterPlugin;
import betteripfilter.DenyReason;
import betteripfilter.IpStore;
import betteripfilter.Ipv4;
import net.kyori.adventure.text.Component;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;

public class IpFilterListener implements Listener {
    private final BetterIpFilterPlugin plugin;
    private final IpStore store;

    public IpFilterListener(BetterIpFilterPlugin plugin, IpStore store) {
        this.plugin = plugin;
        this.store = store;
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onPreLogin(AsyncPlayerPreLoginEvent event) {
        if (!plugin.isFilteringEnabled()) return;

        int ipInt = Ipv4.fromInetAddress(event.getAddress());
        String name  = event.getName();
        String ipStr = ipInt != Ipv4.INVALID
                ? Ipv4.toString(ipInt)
                : event.getAddress().getHostAddress();

        // Cannot parse IP — treat as failsafe condition.
        if (ipInt == Ipv4.INVALID) {
            handleFailsafe(event, name, ipStr);
            return;
        }

        // Proxy gate: only allow connections from trusted proxy IPs.
        if (plugin.isProxyGateEnabled() && !plugin.isTrustedProxy(ipInt)) {
            deny(event, plugin.prefixedComponent(plugin.msg("proxyNotTrusted")));
            plugin.handleDenied(DenyReason.PROXY_NOT_TRUSTED, name, ipStr);
            return;
        }

        // Rate limiting.
        if (plugin.isRateLimitEnabled()
                && !plugin.getRateLimiter().tryAcquire(
                        ipInt, plugin.getRateLimitWindowMillis(), plugin.getRateLimitMaxAttempts())) {
            deny(event, plugin.prefixedComponent(plugin.getRateLimitMessage()));
            plugin.handleDenied(DenyReason.RATE_LIMIT, name, ipStr);
            return;
        }

        // Whitelist store unavailable — apply failsafe policy.
        if (!store.isAvailable()) {
            handleFailsafe(event, name, ipStr);
            return;
        }

        // Whitelist check.
        if (!store.isAllowed(ipInt)) {
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_WHITELIST,
                    plugin.prefixedComponent(plugin.msg("notAllowed")));
            plugin.handleDenied(DenyReason.NOT_WHITELISTED, name, ipStr);
        }
    }

    /**
     * Applies the configured failsafe policy: DENY_ALL kicks the player,
     * ALLOW_ALL lets them through (but the condition is still logged when denied).
     */
    private void handleFailsafe(AsyncPlayerPreLoginEvent event, String name, String ipStr) {
        if (plugin.isFailsafeDenyAll()) {
            deny(event, plugin.prefixedComponent(plugin.getFailsafeMessage()));
            plugin.handleDenied(DenyReason.FAILSAFE, name, ipStr);
        }
        // ALLOW_ALL: do nothing — player proceeds.
    }

    private static void deny(AsyncPlayerPreLoginEvent event, Component message) {
        event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, message);
    }
}

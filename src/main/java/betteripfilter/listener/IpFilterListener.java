package betteripfilter.listener;

import betteripfilter.BetterIpFilterPlugin;
import betteripfilter.DenyReason;
import betteripfilter.IpStore;
import betteripfilter.Ipv4;
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

    @SuppressWarnings("deprecation")
    @EventHandler(priority = EventPriority.HIGHEST)
    public void onPreLogin(AsyncPlayerPreLoginEvent event) {
        if (!plugin.isFilteringEnabled()) {
            return;
        }

        int ipInt = Ipv4.fromInetAddress(event.getAddress());
        String name = event.getName();

        if (ipInt == Ipv4.INVALID) {
            if (plugin.isFailsafeDenyAll()) {
                event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                        plugin.prefixed(plugin.getFailsafeMessage()));
                plugin.handleDenied(DenyReason.FAILSAFE, name, event.getAddress().getHostAddress());
            }
            return;
        }

        if (plugin.isProxyGateEnabled() && plugin.hasTrustedForwardedIps() && !plugin.isTrustedProxy(ipInt)) {
            if (plugin.isFailsafeDenyAll()) {
                event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                        plugin.prefixed(plugin.msg("proxyNotTrusted")));
                plugin.handleDenied(DenyReason.PROXY_NOT_TRUSTED, name, Ipv4.toString(ipInt));
            }
            return;
        }

        if (plugin.isRateLimitEnabled()) {
            if (!plugin.getRateLimiter().tryAcquire(ipInt, plugin.getRateLimitWindowMillis(),
                    plugin.getRateLimitMaxAttempts())) {
                event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                        plugin.prefixed(plugin.getRateLimitMessage()));
                plugin.handleDenied(DenyReason.RATE_LIMIT, name, Ipv4.toString(ipInt));
                return;
            }
        }

        if (!store.isAvailable()) {
            if (plugin.isFailsafeDenyAll()) {
                event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                        plugin.prefixed(plugin.getFailsafeMessage()));
                plugin.handleDenied(DenyReason.FAILSAFE, name, Ipv4.toString(ipInt));
            }
            return;
        }

        if (!store.isAllowed(ipInt)) {
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_WHITELIST,
                    plugin.prefixed(plugin.msg("notAllowed")));
            plugin.handleDenied(DenyReason.NOT_WHITELISTED, name, Ipv4.toString(ipInt));
        }
    }
}

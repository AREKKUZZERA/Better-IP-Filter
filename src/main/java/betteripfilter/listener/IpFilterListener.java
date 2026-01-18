package betteripfilter.listener;

import betteripfilter.BetterIpFilterPlugin;
import betteripfilter.DenyReason;
import betteripfilter.IpStore;
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

        String ip = plugin.resolveClientIp(event);
        String name = event.getName();

        if (plugin.isRateLimitEnabled()) {
            if (!plugin.getRateLimiter().tryAcquire(ip, plugin.getRateLimitWindowMillis(), plugin.getRateLimitMaxAttempts())) {
                event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                    plugin.prefixed(plugin.getRateLimitMessage())
                );
                plugin.handleDenied(DenyReason.RATE_LIMIT, name, ip);
                return;
            }
        }

        if (!store.isAvailable()) {
            if (plugin.isFailsafeDenyAll()) {
                event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                    plugin.prefixed(plugin.getFailsafeMessage())
                );
                plugin.handleDenied(DenyReason.FAILSAFE, name, ip);
            }
            return;
        }

        if (!store.isAllowed(ip)) {
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_WHITELIST,
                plugin.prefixed(plugin.msg("notAllowed"))
            );
            plugin.handleDenied(DenyReason.NOT_WHITELISTED, name, ip);
        }
    }
}

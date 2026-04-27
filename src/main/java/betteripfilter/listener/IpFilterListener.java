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

import java.util.OptionalInt;

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

        OptionalInt parsedIp = Ipv4.fromInetAddressOptional(event.getAddress());
        String name = event.getName();
        String ipStr = parsedIp.isPresent()
                ? Ipv4.toString(parsedIp.getAsInt())
                : event.getAddress().getHostAddress();

        if (parsedIp.isEmpty()) {
            handleFailsafe(event, name, ipStr);
            return;
        }
        int ipInt = parsedIp.getAsInt();

        if (plugin.isProxyGateEnabled() && !plugin.isTrustedProxy(ipInt)) {
            deny(event, plugin.prefixedComponent(plugin.msg("proxyNotTrusted")));
            plugin.handleDenied(DenyReason.PROXY_NOT_TRUSTED, name, ipStr);
            return;
        }

        if (plugin.isRateLimitEnabled()
                && !plugin.getRateLimiter().tryAcquire(
                        ipInt, plugin.getRateLimitWindowMillis(), plugin.getRateLimitMaxAttempts())) {
            deny(event, plugin.prefixedComponent(plugin.getRateLimitMessage()));
            plugin.handleDenied(DenyReason.RATE_LIMIT, name, ipStr);
            return;
        }

        if (!store.isAvailable()) {
            handleFailsafe(event, name, ipStr);
            return;
        }

        if (!store.isAllowed(ipInt)) {
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_WHITELIST,
                    plugin.prefixedComponent(plugin.msg("notAllowed")));
            plugin.handleDenied(DenyReason.NOT_WHITELISTED, name, ipStr);
        }
    }

    private void handleFailsafe(AsyncPlayerPreLoginEvent event, String name, String ipStr) {
        if (plugin.isFailsafeDenyAll()) {
            deny(event, plugin.prefixedComponent(plugin.getFailsafeMessage()));
            plugin.handleDenied(DenyReason.FAILSAFE, name, ipStr);
        }
    }

    private static void deny(AsyncPlayerPreLoginEvent event, Component message) {
        event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, message);
    }
}

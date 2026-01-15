package betteripfilter.listener;

import betteripfilter.BetterIpFilterPlugin;
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

        String ip = event.getAddress().getHostAddress();
        if (!store.isAllowed(ip)) {
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_WHITELIST,
                plugin.prefixed(plugin.msg("notAllowed"))
            );
        }
    }
}

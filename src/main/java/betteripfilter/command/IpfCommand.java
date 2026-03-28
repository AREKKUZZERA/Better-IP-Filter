package betteripfilter.command;

import betteripfilter.BetterIpFilterPlugin;
import betteripfilter.IpStore;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;

import java.util.List;
import java.util.Locale;

public class IpfCommand implements CommandExecutor {
    private final BetterIpFilterPlugin plugin;
    private final IpStore store;

    public IpfCommand(BetterIpFilterPlugin plugin, IpStore store) {
        this.plugin = plugin;
        this.store  = store;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (args.length == 0) { sendUsage(sender); return true; }

        return switch (args[0].toLowerCase(Locale.ROOT)) {
            case "add"    -> handleAdd(sender, args);
            case "remove" -> handleRemove(sender, args);
            case "list"   -> handleList(sender);
            case "status" -> handleStatus(sender);
            case "reload" -> handleReload(sender);
            case "on"     -> handleToggle(sender, true);
            case "off"    -> handleToggle(sender, false);
            default       -> { sendUsage(sender); yield true; }
        };
    }

    private boolean handleAdd(CommandSender sender, String[] args) {
        if (!hasPermission(sender, "betteripfilter.add")) return true;
        if (args.length < 2) { sendUsage(sender); return true; }

        String entry = args[1];
        if (!store.isValidEntry(entry)) {
            send(sender, plugin.msg("invalidIp").replace("{ip}", entry));
            return true;
        }
        if (!store.isAvailable()) {
            send(sender, plugin.msg("storeUnavailable"));
            return true;
        }
        if (store.contains(entry)) {
            send(sender, plugin.msg("alreadyExists").replace("{ip}", entry));
            return true;
        }

        if (store.add(entry)) {
            send(sender, plugin.msg("added").replace("{ip}", entry));
        } else if (!store.isAvailable()) {
            send(sender, plugin.msg("storeUnavailable"));
        } else {
            send(sender, plugin.msg("failedUpdate").replace("{ip}", entry));
        }
        return true;
    }

    private boolean handleRemove(CommandSender sender, String[] args) {
        if (!hasPermission(sender, "betteripfilter.remove")) return true;
        if (args.length < 2) { sendUsage(sender); return true; }

        String entry = args[1];
        if (!store.isValidEntry(entry)) {
            send(sender, plugin.msg("invalidIp").replace("{ip}", entry));
            return true;
        }
        if (!store.isAvailable()) {
            send(sender, plugin.msg("storeUnavailable"));
            return true;
        }
        if (!store.contains(entry)) {
            send(sender, plugin.msg("notFound").replace("{ip}", entry));
            return true;
        }

        if (store.remove(entry)) {
            send(sender, plugin.msg("removed").replace("{ip}", entry));
        } else if (!store.isAvailable()) {
            send(sender, plugin.msg("storeUnavailable"));
        } else {
            send(sender, plugin.msg("failedUpdate").replace("{ip}", entry));
        }
        return true;
    }

    private boolean handleList(CommandSender sender) {
        if (!hasPermission(sender, "betteripfilter.list")) return true;
        List<String> ips = store.list();
        send(sender, plugin.msg("listHeader").replace("{count}", String.valueOf(ips.size())));
        if (ips.isEmpty()) {
            send(sender, "&7- (empty)");
        } else {
            // Send in chunks of 10 to avoid chat overflow
            for (int i = 0; i < ips.size(); i += 10) {
                send(sender, "&f" + String.join("&7, &f", ips.subList(i, Math.min(ips.size(), i + 10))));
            }
        }
        return true;
    }

    private boolean handleStatus(CommandSender sender) {
        if (!hasPermission(sender, "betteripfilter.status")) return true;
        send(sender, plugin.msg("statusHeader"));
        send(sender, "&7Enabled: &f"          + plugin.isFilteringEnabled());
        send(sender, "&7Store available: &f"  + store.isAvailable());
        send(sender, "&7Whitelist entries: &f" + store.list().size());
        send(sender, "&7Proxy mode: &f"       + plugin.getProxyMode()
                + " &7(trusted: &f"           + plugin.getTrustedForwardedIpsCount() + "&7)");
        send(sender, "&7Rate limit: &f"       + plugin.isRateLimitEnabled()
                + " &7(window: &f"            + (plugin.getRateLimitWindowMillis() / 1000L)
                + "s&7, max: &f"              + plugin.getRateLimitMaxAttempts() + "&7)");
        send(sender, "&7Failsafe mode: &f"    + plugin.getFailsafeMode());
        send(sender, "&7Webhook: &f"          + plugin.isWebhookEnabled()
                + " &7(configured: &f"        + (plugin.isWebhookConfigured() ? "yes" : "no") + "&7)");
        if (!store.isAvailable() && store.getLastError() != null) {
            send(sender, "&cStore error: &f" + store.getLastError());
        }
        return true;
    }

    private boolean handleReload(CommandSender sender) {
        if (!hasPermission(sender, "betteripfilter.reload")) return true;
        try {
            plugin.reloadConfig();
            plugin.loadSettings();
            store.load();
            send(sender, plugin.msg(store.isAvailable() ? "reloaded" : "failedUpdate"));
        } catch (Exception ex) {
            send(sender, plugin.msg("failedUpdate"));
            plugin.getLogger().warning("Reload failed: " + ex.getMessage());
        }
        return true;
    }

    private boolean handleToggle(CommandSender sender, boolean enabled) {
        if (!hasPermission(sender, "betteripfilter.toggle")) return true;
        plugin.setFilteringEnabled(enabled);
        send(sender, plugin.msg(enabled ? "enabled" : "disabled"));
        return true;
    }

    private boolean hasPermission(CommandSender sender, String perm) {
        if (sender.hasPermission("betteripfilter.admin") || sender.hasPermission(perm)) return true;
        send(sender, plugin.msg("noPermission"));
        return false;
    }

    private void send(CommandSender sender, String message) {
        sender.sendMessage(plugin.prefixedComponent(message));
    }

    private void sendUsage(CommandSender sender) {
        send(sender, "&cUsage: /ipf <subcommand>");
        send(sender, "&7/ipf add <ip|cidr|range>  &f- add to whitelist");
        send(sender, "&7/ipf remove <entry>        &f- remove from whitelist");
        send(sender, "&7/ipf list                  &f- list all entries");
        send(sender, "&7/ipf status                &f- plugin diagnostics");
        send(sender, "&7/ipf reload                &f- reload config + whitelist");
        send(sender, "&7/ipf on|off                &f- toggle filtering");
    }
}

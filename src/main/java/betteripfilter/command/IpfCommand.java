package betteripfilter.command;

import betteripfilter.BetterIpFilterPlugin;
import betteripfilter.IpStore;
import org.bukkit.ChatColor;
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
        this.store = store;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (args.length == 0) {
            sendUsage(sender);
            return true;
        }

        String sub = args[0].toLowerCase(Locale.ROOT);
        switch (sub) {
            case "add":
                return handleAdd(sender, args);
            case "remove":
                return handleRemove(sender, args);
            case "list":
                return handleList(sender);
            case "status":
                return handleStatus(sender);
            case "reload":
                return handleReload(sender);
            case "on":
                return handleToggle(sender, true);
            case "off":
                return handleToggle(sender, false);
            default:
                sendUsage(sender);
                return true;
        }
    }

    private boolean handleAdd(CommandSender sender, String[] args) {
        if (!hasPermission(sender, "betteripfilter.add")) {
            return true;
        }
        if (args.length < 2) {
            sendUsage(sender);
            return true;
        }
        if (!store.isAvailable()) {
            sender.sendMessage(plugin.prefixed(plugin.msg("storeUnavailable")));
            return true;
        }
        String ip = args[1];
        if (!store.isValidIp(ip)) {
            sender.sendMessage(plugin.prefixed(plugin.msg("invalidIp").replace("{ip}", ip)));
            return true;
        }
        if (store.contains(ip)) {
            sender.sendMessage(plugin.prefixed(plugin.msg("alreadyExists").replace("{ip}", ip)));
            return true;
        }
        if (store.add(ip)) {
            sender.sendMessage(plugin.prefixed(plugin.msg("added").replace("{ip}", ip)));
        } else if (!store.isAvailable()) {
            sender.sendMessage(plugin.prefixed(plugin.msg("storeUnavailable")));
        } else {
            sender.sendMessage(plugin.prefixed(plugin.msg("failedUpdate").replace("{ip}", ip)));
        }
        return true;
    }

    private boolean handleRemove(CommandSender sender, String[] args) {
        if (!hasPermission(sender, "betteripfilter.remove")) {
            return true;
        }
        if (args.length < 2) {
            sendUsage(sender);
            return true;
        }
        if (!store.isAvailable()) {
            sender.sendMessage(plugin.prefixed(plugin.msg("storeUnavailable")));
            return true;
        }
        String ip = args[1];
        if (!store.isValidIp(ip)) {
            sender.sendMessage(plugin.prefixed(plugin.msg("invalidIp").replace("{ip}", ip)));
            return true;
        }
        if (!store.contains(ip)) {
            sender.sendMessage(plugin.prefixed(plugin.msg("notFound").replace("{ip}", ip)));
        } else if (store.remove(ip)) {
            sender.sendMessage(plugin.prefixed(plugin.msg("removed").replace("{ip}", ip)));
        } else if (!store.isAvailable()) {
            sender.sendMessage(plugin.prefixed(plugin.msg("storeUnavailable")));
        } else {
            sender.sendMessage(plugin.prefixed(plugin.msg("failedUpdate").replace("{ip}", ip)));
        }
        return true;
    }

    @SuppressWarnings("deprecation")
    private boolean handleList(CommandSender sender) {
        if (!hasPermission(sender, "betteripfilter.list")) {
            return true;
        }
        List<String> ips = store.list();
        sender.sendMessage(plugin.prefixed(plugin.msg("listHeader").replace("{count}", String.valueOf(ips.size()))));
        if (ips.isEmpty()) {
            sender.sendMessage(plugin.prefixed(ChatColor.GRAY + "- (empty)"));
        } else {
            int chunkSize = 10;
            for (int i = 0; i < ips.size(); i += chunkSize) {
                int end = Math.min(ips.size(), i + chunkSize);
                sender.sendMessage(plugin.prefixed(String.join(", ", ips.subList(i, end))));
            }
        }
        return true;
    }

    private boolean handleStatus(CommandSender sender) {
        if (!hasPermission(sender, "betteripfilter.status")) {
            return true;
        }
        sender.sendMessage(plugin.prefixed(plugin.msg("statusHeader")));
        sender.sendMessage(plugin.prefixed("&7Enabled: &f" + plugin.isFilteringEnabled()));
        sender.sendMessage(plugin.prefixed("&7Store available: &f" + store.isAvailable()));
        sender.sendMessage(plugin.prefixed("&7Whitelist entries: &f" + store.list().size()));
        sender.sendMessage(plugin.prefixed("&7Proxy mode: &f" + plugin.getProxyMode()
                + " &7(trusted: &f" + plugin.getTrustedForwardedIpsCount() + "&7)"));
        sender.sendMessage(plugin.prefixed("&7Rate limit: &f" + plugin.isRateLimitEnabled()
                + " &7(window: &f" + (plugin.getRateLimitWindowMillis() / 1000L)
                + "s&7, max: &f" + plugin.getRateLimitMaxAttempts() + "&7)"));
        sender.sendMessage(plugin.prefixed("&7Failsafe mode: &f" + plugin.getFailsafeMode()));
        sender.sendMessage(plugin.prefixed("&7Webhook enabled: &f" + plugin.isWebhookEnabled()
                + " &7(configured: &f" + (plugin.isWebhookConfigured() ? "yes" : "no") + "&7)"));
        return true;
    }

    private boolean handleReload(CommandSender sender) {
        if (!hasPermission(sender, "betteripfilter.reload")) {
            return true;
        }
        try {
            plugin.reloadConfig();
            plugin.loadSettings();
            store.load();
            if (store.isAvailable()) {
                sender.sendMessage(plugin.prefixed(plugin.msg("reloaded")));
            } else {
                sender.sendMessage(plugin.prefixed(plugin.msg("failedUpdate")));
            }
        } catch (Exception ex) {
            sender.sendMessage(plugin.prefixed(plugin.msg("failedUpdate")));
            plugin.getLogger().warning("Failed to reload configuration: " + ex.getMessage());
        }
        return true;
    }

    private boolean handleToggle(CommandSender sender, boolean enabled) {
        if (!hasPermission(sender, "betteripfilter.toggle")) {
            return true;
        }
        plugin.setFilteringEnabled(enabled);
        String key = enabled ? "enabled" : "disabled";
        sender.sendMessage(plugin.prefixed(plugin.msg(key)));
        return true;
    }

    private boolean hasPermission(CommandSender sender, String permission) {
        if (sender.hasPermission("betteripfilter.admin") || sender.hasPermission(permission)) {
            return true;
        }
        sender.sendMessage(plugin.prefixed(plugin.msg("noPermission")));
        return false;
    }

    private void sendUsage(CommandSender sender) {
        sender.sendMessage(plugin.prefixed("&cUsage: /ipf <subcommand>"));
        sender.sendMessage(plugin.prefixed("&7/ipf add <ip> &f- add IPv4/CIDR/range"));
        sender.sendMessage(plugin.prefixed("&7/ipf remove <ip> &f- remove entry"));
        sender.sendMessage(plugin.prefixed("&7/ipf list &f- list whitelist entries"));
        sender.sendMessage(plugin.prefixed("&7/ipf status &f- plugin diagnostics"));
        sender.sendMessage(plugin.prefixed("&7/ipf reload &f- reload config + whitelist"));
        sender.sendMessage(plugin.prefixed("&7/ipf on|off &f- toggle filtering"));
    }
}

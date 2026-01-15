package betteripfilter.command;

import betteripfilter.BetterIpFilterPlugin;
import betteripfilter.IpStore;
import org.bukkit.ChatColor;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;

import java.util.List;

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

        String sub = args[0].toLowerCase();
        switch (sub) {
            case "add":
                return handleAdd(sender, args);
            case "remove":
                return handleRemove(sender, args);
            case "list":
                return handleList(sender);
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
        String ip = args[1];
        if (!store.isValidIp(ip)) {
            sender.sendMessage(plugin.prefixed(plugin.msg("invalidIp").replace("{ip}", ip)));
            return true;
        }
        store.add(ip);
        sender.sendMessage(plugin.prefixed(plugin.msg("added").replace("{ip}", ip)));
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
        String ip = args[1];
        if (!store.isValidIp(ip)) {
            sender.sendMessage(plugin.prefixed(plugin.msg("invalidIp").replace("{ip}", ip)));
            return true;
        }
        if (store.remove(ip)) {
            sender.sendMessage(plugin.prefixed(plugin.msg("removed").replace("{ip}", ip)));
        } else {
            sender.sendMessage(plugin.prefixed(plugin.msg("notFound").replace("{ip}", ip)));
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
            sender.sendMessage(plugin.prefixed(String.join(", ", ips)));
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
        sender.sendMessage(plugin.prefixed("&cUsage: /ipf <add|remove|list|on|off>"));
    }
}

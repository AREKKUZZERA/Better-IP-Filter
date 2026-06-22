package betteripfilter.command;

import betteripfilter.BetterIpFilterPlugin;
import betteripfilter.IpStore;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;

import java.time.Instant;
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
            case "addtemp" -> handleAddTemp(sender, args);
            case "remove" -> handleRemove(sender, args);
            case "list"   -> handleList(sender);
            case "check"  -> handleCheck(sender, args);
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
        String note = joinArgs(args, 2);
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

        String normalized = store.normalizeEntry(entry);
        if (store.add(entry, note)) {
            send(sender, plugin.msg("added").replace("{ip}", normalized));
        } else if (!store.isAvailable()) {
            send(sender, plugin.msg("storeUnavailable"));
        } else {
            send(sender, plugin.msg("failedUpdate").replace("{ip}", entry));
        }
        return true;
    }

    private boolean handleAddTemp(CommandSender sender, String[] args) {
        if (!hasPermission(sender, "betteripfilter.add")) return true;
        if (args.length < 3) {
            send(sender, "&cUsage: /ipf addtemp <ip|cidr|range> <duration> [note]");
            return true;
        }

        String entry = args[1];
        String normalized = store.normalizeEntry(entry);
        if (normalized == null) {
            send(sender, plugin.msg("invalidIp").replace("{ip}", entry));
            return true;
        }
        if (!store.isAvailable()) {
            send(sender, plugin.msg("storeUnavailable"));
            return true;
        }
        if (store.contains(entry)) {
            send(sender, plugin.msg("alreadyExists").replace("{ip}", normalized));
            return true;
        }

        long durationMillis = parseDurationMillis(args[2]);
        if (durationMillis <= 0) {
            send(sender, "&cInvalid duration: &f" + args[2] + " &7(use 30m, 2h, 7d)");
            return true;
        }

        long expiresAt = System.currentTimeMillis() + durationMillis;
        if (store.addTemporary(entry, expiresAt, joinArgs(args, 3))) {
            send(sender, "&aAdded temporary: &f" + normalized + " &7(expires: &f" + Instant.ofEpochMilli(expiresAt) + "&7)");
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

        String normalized = store.normalizeEntry(entry);
        if (store.remove(entry)) {
            send(sender, plugin.msg("removed").replace("{ip}", normalized));
        } else if (!store.isAvailable()) {
            send(sender, plugin.msg("storeUnavailable"));
        } else {
            send(sender, plugin.msg("failedUpdate").replace("{ip}", entry));
        }
        return true;
    }

    private boolean handleList(CommandSender sender) {
        if (!hasPermission(sender, "betteripfilter.list")) return true;
        List<IpStore.EntryView> entries = store.listEntries();
        send(sender, plugin.msg("listHeader").replace("{count}", String.valueOf(entries.size())));
        if (entries.isEmpty()) {
            send(sender, "&7- (empty)");
        } else {
            for (IpStore.EntryView entry : entries) {
                StringBuilder line = new StringBuilder("&f").append(entry.value());
                if (entry.note() != null && !entry.note().isBlank()) {
                    line.append(" &7- &f").append(entry.note());
                }
                if (entry.expiresAtMillis() != null) {
                    line.append(" &7(expires: &f").append(Instant.ofEpochMilli(entry.expiresAtMillis())).append("&7)");
                }
                send(sender, line.toString());
            }
        }
        return true;
    }

    private boolean handleCheck(CommandSender sender, String[] args) {
        if (!hasPermission(sender, "betteripfilter.status")) return true;
        if (args.length < 2) {
            send(sender, "&cUsage: /ipf check <ip>");
            return true;
        }

        IpStore.CheckResult result = store.check(args[1]);
        if (!result.valid()) {
            send(sender, plugin.msg("invalidIp").replace("{ip}", args[1]));
            return true;
        }
        if (!store.isAvailable()) {
            send(sender, plugin.msg("storeUnavailable"));
            return true;
        }
        if (!result.allowed()) {
            send(sender, "&cDenied: &f" + result.ip() + " &7(no matching whitelist entry)");
            return true;
        }

        StringBuilder line = new StringBuilder("&aAllowed: &f")
                .append(result.ip())
                .append(" &7matches &f")
                .append(result.matchedEntry());
        if (result.note() != null && !result.note().isBlank()) {
            line.append(" &7- &f").append(result.note());
        }
        if (result.expiresAtMillis() != null) {
            line.append(" &7(expires: &f").append(Instant.ofEpochMilli(result.expiresAtMillis())).append("&7)");
        }
        send(sender, line.toString());
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
        send(sender, "&7Denied counters: &fnot-whitelisted=" + plugin.getDeniedNotWhitelistedCount()
                + "&7, proxy=" + plugin.getDeniedProxyNotTrustedCount()
                + "&7, ratelimit=" + plugin.getDeniedRateLimitCount()
                + "&7, failsafe=" + plugin.getDeniedFailsafeCount());
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
        send(sender, "&7/ipf add <ip|cidr|range> [note] &f- add to whitelist");
        send(sender, "&7/ipf addtemp <entry> <duration> [note] &f- add temporary entry");
        send(sender, "&7/ipf remove <entry>        &f- remove from whitelist");
        send(sender, "&7/ipf check <ip>            &f- explain whitelist match");
        send(sender, "&7/ipf list                  &f- list all entries");
        send(sender, "&7/ipf status                &f- plugin diagnostics");
        send(sender, "&7/ipf reload                &f- reload config + whitelist");
        send(sender, "&7/ipf on|off                &f- toggle filtering");
    }

    private static String joinArgs(String[] args, int start) {
        if (args.length <= start) return "";
        return String.join(" ", List.of(args).subList(start, args.length));
    }

    private static long parseDurationMillis(String value) {
        if (value == null || value.length() < 2) return -1;
        String number = value.substring(0, value.length() - 1);
        char unit = Character.toLowerCase(value.charAt(value.length() - 1));
        long amount;
        try {
            amount = Long.parseLong(number);
        } catch (NumberFormatException e) {
            return -1;
        }
        if (amount <= 0) return -1;
        return switch (unit) {
            case 's' -> amount * 1000L;
            case 'm' -> amount * 60_000L;
            case 'h' -> amount * 3_600_000L;
            case 'd' -> amount * 86_400_000L;
            default -> -1;
        };
    }
}

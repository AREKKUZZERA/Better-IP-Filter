package betteripfilter.command;

import betteripfilter.IpStore;
import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabCompleter;

import java.util.List;
import java.util.Locale;

public class IpfTabCompleter implements TabCompleter {
    private static final List<String> SUBCOMMANDS =
            List.of("add", "remove", "list", "status", "reload", "on", "off");

    private final IpStore store;

    public IpfTabCompleter(IpStore store) {
        this.store = store;
    }

    @Override
    public List<String> onTabComplete(CommandSender sender, Command command, String alias, String[] args) {
        if (args.length == 1) return filterPrefix(SUBCOMMANDS, args[0]);
        if (args.length == 2 && "remove".equalsIgnoreCase(args[0])) return filterPrefix(store.list(), args[1]);
        return List.of();
    }

    private static List<String> filterPrefix(List<String> options, String prefix) {
        String lower = prefix.toLowerCase(Locale.ROOT);
        return options.stream()
                .filter(o -> o.toLowerCase(Locale.ROOT).startsWith(lower))
                .toList();
    }
}

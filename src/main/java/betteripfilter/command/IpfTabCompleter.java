package betteripfilter.command;

import betteripfilter.IpStore;
import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabCompleter;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;

public class IpfTabCompleter implements TabCompleter {
    private final IpStore store;

    public IpfTabCompleter(IpStore store) {
        this.store = store;
    }

    @Override
    public List<String> onTabComplete(CommandSender sender, Command command, String alias, String[] args) {
        if (args.length == 1) {
            return filterPrefix(Arrays.asList("add", "remove", "list", "on", "off"), args[0]);
        }
        if (args.length == 2 && "remove".equalsIgnoreCase(args[0])) {
            return filterPrefix(store.list(), args[1]);
        }
        return new ArrayList<>();
    }

    private List<String> filterPrefix(List<String> options, String prefix) {
        String lower = prefix.toLowerCase(Locale.ROOT);
        return options.stream()
            .filter(option -> option.toLowerCase(Locale.ROOT).startsWith(lower))
            .collect(Collectors.toList());
    }
}

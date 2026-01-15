package betteripfilter;

import betteripfilter.command.IpfCommand;
import betteripfilter.command.IpfTabCompleter;
import betteripfilter.listener.IpFilterListener;
import org.bukkit.ChatColor;
import org.bukkit.command.PluginCommand;
import org.bukkit.plugin.java.JavaPlugin;

public class BetterIpFilterPlugin extends JavaPlugin {
    private IpStore ipStore;

    @Override
    public void onEnable() {
        saveDefaultConfig();

        ipStore = new IpStore(this);
        ipStore.load();

        getServer().getPluginManager().registerEvents(new IpFilterListener(this, ipStore), this);

        PluginCommand command = getCommand("ipf");
        if (command != null) {
            IpfCommand executor = new IpfCommand(this, ipStore);
            command.setExecutor(executor);
            command.setTabCompleter(new IpfTabCompleter(ipStore));
        } else {
            getLogger().severe("Command 'ipf' not found in plugin.yml");
        }
    }

    public boolean isFilteringEnabled() {
        return getConfig().getBoolean("enabled", true);
    }

    public void setFilteringEnabled(boolean enabled) {
        getConfig().set("enabled", enabled);
        saveConfig();
    }

    public String color(String message) {
        return ChatColor.translateAlternateColorCodes('&', message);
    }

    public String msg(String key) {
        return getConfig().getString("messages." + key, "");
    }

    public String prefixed(String message) {
        return color(msg("prefix") + message);
    }
}

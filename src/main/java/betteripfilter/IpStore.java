package betteripfilter;

import org.bukkit.configuration.file.YamlConfiguration;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.regex.Pattern;

public class IpStore {
    private static final Pattern IPV4_PATTERN = Pattern.compile(
        "^(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}$"
    );

    private final BetterIpFilterPlugin plugin;
    private final File file;
    private final Set<String> ips = new HashSet<>();
    private final ReadWriteLock lock = new ReentrantReadWriteLock();

    public IpStore(BetterIpFilterPlugin plugin) {
        this.plugin = plugin;
        this.file = new File(plugin.getDataFolder(), "ips.yml");
    }

    public void load() {
        if (!plugin.getDataFolder().exists() && !plugin.getDataFolder().mkdirs()) {
            plugin.getLogger().severe("Failed to create plugin data folder.");
            return;
        }

        if (!file.exists()) {
            return;
        }

        YamlConfiguration config = YamlConfiguration.loadConfiguration(file);
        List<String> loaded = config.getStringList("ips");

        lock.writeLock().lock();
        try {
            ips.clear();
            for (String ip : loaded) {
                if (isValidIp(ip)) {
                    ips.add(ip);
                }
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    public boolean isAllowed(String ip) {
        lock.readLock().lock();
        try {
            return ips.contains(ip);
        } finally {
            lock.readLock().unlock();
        }
    }

    public boolean add(String ip) {
        lock.writeLock().lock();
        try {
            if (!ips.add(ip)) {
                return false;
            }
            save();
            return true;
        } finally {
            lock.writeLock().unlock();
        }
    }

    public boolean remove(String ip) {
        lock.writeLock().lock();
        try {
            if (!ips.remove(ip)) {
                return false;
            }
            save();
            return true;
        } finally {
            lock.writeLock().unlock();
        }
    }

    public List<String> list() {
        lock.readLock().lock();
        try {
            List<String> result = new ArrayList<>(ips);
            Collections.sort(result);
            return result;
        } finally {
            lock.readLock().unlock();
        }
    }

    public boolean isValidIp(String ip) {
        return ip != null && IPV4_PATTERN.matcher(ip).matches();
    }

    private void save() {
        if (!plugin.getDataFolder().exists() && !plugin.getDataFolder().mkdirs()) {
            plugin.getLogger().severe("Failed to create plugin data folder.");
            return;
        }

        YamlConfiguration config = new YamlConfiguration();
        config.set("ips", list());
        try {
            config.save(file);
        } catch (IOException e) {
            plugin.getLogger().severe("Failed to save ips.yml: " + e.getMessage());
        }
    }
}

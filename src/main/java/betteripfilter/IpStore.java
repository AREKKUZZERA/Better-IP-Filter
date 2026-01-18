package betteripfilter;

import org.bukkit.configuration.file.YamlConfiguration;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class IpStore {
    private final BetterIpFilterPlugin plugin;
    private final File file;
    private final Object writeLock = new Object();
    private final Set<String> entries = new HashSet<>();
    private volatile Snapshot snapshot = Snapshot.empty();
    private volatile boolean available = true;
    private volatile String lastError;

    public IpStore(BetterIpFilterPlugin plugin) {
        this.plugin = plugin;
        this.file = new File(plugin.getDataFolder(), "ips.yml");
    }

    public void load() {
        synchronized (writeLock) {
            if (!plugin.getDataFolder().exists() && !plugin.getDataFolder().mkdirs()) {
                available = false;
                lastError = "Failed to create plugin data folder.";
                plugin.getLogger().severe(lastError);
                return;
            }

            if (!file.exists()) {
                entries.clear();
                snapshot = Snapshot.empty();
                available = true;
                lastError = null;
                return;
            }

            YamlConfiguration config = YamlConfiguration.loadConfiguration(file);
            List<String> loaded = config.getStringList("ips");

            ParseResult result = parseEntries(loaded);
            if (!result.success) {
                available = false;
                lastError = result.errorMessage;
                plugin.getLogger().warning("Failed to load ips.yml: " + result.errorMessage);
                return;
            }

            entries.clear();
            entries.addAll(result.entries);
            snapshot = result.snapshot;
            available = true;
            lastError = null;
        }
    }

    public boolean isAvailable() {
        return available;
    }

    public String getLastError() {
        return lastError;
    }

    public boolean isAllowed(String ip) {
        int ipInt = parseIpv4ToInt(ip);
        if (ipInt < 0) {
            return false;
        }

        Snapshot current = snapshot;
        if (current.exactIps.contains(ipInt)) {
            return true;
        }
        for (IpRange range : current.ranges) {
            if (range.contains(ipInt)) {
                return true;
            }
        }
        for (CidrBlock block : current.cidrBlocks) {
            if (block.contains(ipInt)) {
                return true;
            }
        }
        return false;
    }

    public boolean add(String entry) {
        ParsedEntry parsed = parseEntry(entry);
        if (parsed == null) {
            return false;
        }
        synchronized (writeLock) {
            if (!entries.add(parsed.normalized)) {
                return false;
            }
            ParseResult result = parseEntries(entries);
            if (!result.success) {
                available = false;
                lastError = result.errorMessage;
                plugin.getLogger().warning("Failed to update whitelist: " + result.errorMessage);
                return false;
            }
            snapshot = result.snapshot;
            available = true;
            lastError = null;
            save();
            return true;
        }
    }

    public boolean remove(String entry) {
        ParsedEntry parsed = parseEntry(entry);
        if (parsed == null) {
            return false;
        }
        synchronized (writeLock) {
            if (!entries.remove(parsed.normalized)) {
                return false;
            }
            ParseResult result = parseEntries(entries);
            if (!result.success) {
                available = false;
                lastError = result.errorMessage;
                plugin.getLogger().warning("Failed to update whitelist: " + result.errorMessage);
                return false;
            }
            snapshot = result.snapshot;
            available = true;
            lastError = null;
            save();
            return true;
        }
    }

    public List<String> list() {
        synchronized (writeLock) {
            List<String> result = new ArrayList<>(entries);
            Collections.sort(result);
            return result;
        }
    }

    public boolean isValidIp(String entry) {
        return parseEntry(entry) != null;
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

    private ParseResult parseEntries(Iterable<String> loaded) {
        Set<String> normalizedEntries = new HashSet<>();
        Set<Integer> exactIps = new HashSet<>();
        List<CidrBlock> cidrBlocks = new ArrayList<>();
        List<IpRange> ranges = new ArrayList<>();

        for (String entry : loaded) {
            if (entry == null || entry.isBlank()) {
                continue;
            }
            ParsedEntry parsed = parseEntry(entry);
            if (parsed == null) {
                return ParseResult.failure("Invalid whitelist entry: " + entry);
            }
            normalizedEntries.add(parsed.normalized);
            if (parsed.type == EntryType.EXACT) {
                exactIps.add(parsed.singleIp);
            } else if (parsed.type == EntryType.CIDR) {
                cidrBlocks.add(new CidrBlock(parsed.singleIp, parsed.prefix));
            } else {
                ranges.add(new IpRange(parsed.rangeStart, parsed.rangeEnd));
            }
        }

        return ParseResult.success(normalizedEntries, new Snapshot(exactIps, cidrBlocks, ranges));
    }

    private ParsedEntry parseEntry(String raw) {
        if (raw == null) {
            return null;
        }
        String trimmed = raw.trim();
        if (trimmed.isEmpty()) {
            return null;
        }
        int slashIndex = trimmed.indexOf('/');
        int dashIndex = trimmed.indexOf('-');
        if (slashIndex > -1) {
            if (dashIndex > -1) {
                return null;
            }
            String[] parts = trimmed.split("/", -1);
            if (parts.length != 2) {
                return null;
            }
            int ip = parseIpv4ToInt(parts[0]);
            if (ip < 0) {
                return null;
            }
            int prefix;
            try {
                prefix = Integer.parseInt(parts[1]);
            } catch (NumberFormatException ex) {
                return null;
            }
            if (prefix < 0 || prefix > 32) {
                return null;
            }
            String normalized = intToIp(ip) + "/" + prefix;
            return ParsedEntry.cidr(normalized, ip, prefix);
        }
        if (dashIndex > -1) {
            String[] parts = trimmed.split("-", -1);
            if (parts.length != 2) {
                return null;
            }
            int start = parseIpv4ToInt(parts[0]);
            int end = parseIpv4ToInt(parts[1]);
            if (start < 0 || end < 0) {
                return null;
            }
            if (Integer.compareUnsigned(start, end) > 0) {
                return null;
            }
            String normalized = intToIp(start) + "-" + intToIp(end);
            return ParsedEntry.range(normalized, start, end);
        }
        int ip = parseIpv4ToInt(trimmed);
        if (ip < 0) {
            return null;
        }
        return ParsedEntry.exact(intToIp(ip), ip);
    }

    private int parseIpv4ToInt(String value) {
        if (value == null) {
            return -1;
        }
        String trimmed = value.trim();
        int length = trimmed.length();
        if (length < 7 || length > 15) {
            return -1;
        }
        int result = 0;
        int part = 0;
        int partLength = 0;
        int parts = 0;
        for (int i = 0; i < length; i++) {
            char ch = trimmed.charAt(i);
            if (ch == '.') {
                if (partLength == 0) {
                    return -1;
                }
                result = (result << 8) | part;
                parts++;
                part = 0;
                partLength = 0;
                continue;
            }
            if (ch < '0' || ch > '9') {
                return -1;
            }
            part = part * 10 + (ch - '0');
            partLength++;
            if (part > 255) {
                return -1;
            }
        }
        if (partLength == 0) {
            return -1;
        }
        result = (result << 8) | part;
        parts++;
        if (parts != 4) {
            return -1;
        }
        return result;
    }

    private String intToIp(int value) {
        return (value >>> 24 & 0xFF) + "." +
            (value >>> 16 & 0xFF) + "." +
            (value >>> 8 & 0xFF) + "." +
            (value & 0xFF);
    }

    private enum EntryType {
        EXACT,
        CIDR,
        RANGE
    }

    private static final class ParsedEntry {
        private final String normalized;
        private final EntryType type;
        private final int singleIp;
        private final int prefix;
        private final int rangeStart;
        private final int rangeEnd;

        private ParsedEntry(String normalized, EntryType type, int singleIp, int prefix, int rangeStart, int rangeEnd) {
            this.normalized = normalized;
            this.type = type;
            this.singleIp = singleIp;
            this.prefix = prefix;
            this.rangeStart = rangeStart;
            this.rangeEnd = rangeEnd;
        }

        private static ParsedEntry exact(String normalized, int ip) {
            return new ParsedEntry(normalized, EntryType.EXACT, ip, 0, 0, 0);
        }

        private static ParsedEntry cidr(String normalized, int ip, int prefix) {
            return new ParsedEntry(normalized, EntryType.CIDR, ip, prefix, 0, 0);
        }

        private static ParsedEntry range(String normalized, int start, int end) {
            return new ParsedEntry(normalized, EntryType.RANGE, 0, 0, start, end);
        }
    }

    private static final class ParseResult {
        private final boolean success;
        private final String errorMessage;
        private final Set<String> entries;
        private final Snapshot snapshot;

        private ParseResult(boolean success, String errorMessage, Set<String> entries, Snapshot snapshot) {
            this.success = success;
            this.errorMessage = errorMessage;
            this.entries = entries;
            this.snapshot = snapshot;
        }

        private static ParseResult success(Set<String> entries, Snapshot snapshot) {
            return new ParseResult(true, null, entries, snapshot);
        }

        private static ParseResult failure(String errorMessage) {
            return new ParseResult(false, errorMessage, null, null);
        }
    }

    private static final class Snapshot {
        private final Set<Integer> exactIps;
        private final List<CidrBlock> cidrBlocks;
        private final List<IpRange> ranges;

        private Snapshot(Set<Integer> exactIps, List<CidrBlock> cidrBlocks, List<IpRange> ranges) {
            this.exactIps = Collections.unmodifiableSet(exactIps);
            this.cidrBlocks = Collections.unmodifiableList(cidrBlocks);
            this.ranges = Collections.unmodifiableList(ranges);
        }

        private static Snapshot empty() {
            return new Snapshot(Collections.emptySet(), Collections.emptyList(), Collections.emptyList());
        }
    }

    private static final class CidrBlock {
        private final int network;
        private final int mask;

        private CidrBlock(int ip, int prefix) {
            this.mask = prefix == 0 ? 0 : -1 << (32 - prefix);
            this.network = ip & mask;
        }

        private boolean contains(int ip) {
            return (ip & mask) == network;
        }
    }

    private static final class IpRange {
        private final int start;
        private final int end;

        private IpRange(int start, int end) {
            this.start = start;
            this.end = end;
        }

        private boolean contains(int ip) {
            return Integer.compareUnsigned(ip, start) >= 0 && Integer.compareUnsigned(ip, end) <= 0;
        }
    }
}

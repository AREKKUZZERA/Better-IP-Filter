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
        int ipInt = Ipv4.parseToInt(ip);
        return ipInt != Ipv4.INVALID && isAllowed(ipInt);
    }

    public boolean isAllowed(int ipInt) {
        Snapshot current = snapshot;
        if (current.exactIps.contains(ipInt)) {
            return true;
        }
        return current.containsInRange(ipInt);
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

    public boolean contains(String entry) {
        ParsedEntry parsed = parseEntry(entry);
        if (parsed == null) {
            return false;
        }
        synchronized (writeLock) {
            return entries.contains(parsed.normalized);
        }
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
        List<Range> ranges = new ArrayList<>();
        int exactCount = 0;

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
                exactCount++;
            } else if (parsed.type == EntryType.CIDR) {
                ranges.add(new Range(Ipv4.cidrStart(parsed.singleIp, parsed.prefix), Ipv4.cidrEnd(parsed.singleIp, parsed.prefix)));
            } else {
                ranges.add(new Range(parsed.rangeStart, parsed.rangeEnd));
            }
        }

        IntHashSet exactIps = rebuildExactSet(normalizedEntries, exactCount);
        int[][] merged = mergeRanges(ranges);
        return ParseResult.success(normalizedEntries, new Snapshot(exactIps, merged[0], merged[1]));
    }

    private IntHashSet rebuildExactSet(Set<String> normalizedEntries, int exactCount) {
        IntHashSet exactIps = new IntHashSet(exactCount);
        for (String entry : normalizedEntries) {
            if (entry.indexOf('/') >= 0 || entry.indexOf('-') >= 0) {
                continue;
            }
            int ip = Ipv4.parseToInt(entry);
            if (ip != Ipv4.INVALID) {
                exactIps.add(ip);
            }
        }
        return exactIps;
    }

    private int[][] mergeRanges(List<Range> ranges) {
        if (ranges.isEmpty()) {
            return new int[][]{new int[0], new int[0]};
        }
        ranges.sort((a, b) -> {
            int cmpStart = Integer.compareUnsigned(a.start, b.start);
            if (cmpStart != 0) {
                return cmpStart;
            }
            return Integer.compareUnsigned(a.end, b.end);
        });

        List<Range> merged = new ArrayList<>(ranges.size());
        Range current = ranges.getFirst();
        for (int i = 1; i < ranges.size(); i++) {
            Range next = ranges.get(i);
            if (canMerge(current, next)) {
                if (Integer.compareUnsigned(next.end, current.end) > 0) {
                    current = new Range(current.start, next.end);
                }
            } else {
                merged.add(current);
                current = next;
            }
        }
        merged.add(current);

        int[] starts = new int[merged.size()];
        int[] ends = new int[merged.size()];
        for (int i = 0; i < merged.size(); i++) {
            starts[i] = merged.get(i).start;
            ends[i] = merged.get(i).end;
        }
        return new int[][]{starts, ends};
    }

    private boolean canMerge(Range left, Range right) {
        if (Integer.compareUnsigned(right.start, left.end) <= 0) {
            return true;
        }
        if (left.end == -1) {
            return true;
        }
        return Integer.compareUnsigned(right.start, left.end + 1) == 0;
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
            int ip = Ipv4.parseToInt(parts[0]);
            if (ip == Ipv4.INVALID) {
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
            String normalized = Ipv4.toString(ip) + "/" + prefix;
            return ParsedEntry.cidr(normalized, ip, prefix);
        }
        if (dashIndex > -1) {
            String[] parts = trimmed.split("-", -1);
            if (parts.length != 2) {
                return null;
            }
            int start = Ipv4.parseToInt(parts[0]);
            int end = Ipv4.parseToInt(parts[1]);
            if (start == Ipv4.INVALID || end == Ipv4.INVALID) {
                return null;
            }
            if (Integer.compareUnsigned(start, end) > 0) {
                return null;
            }
            String normalized = Ipv4.toString(start) + "-" + Ipv4.toString(end);
            return ParsedEntry.range(normalized, start, end);
        }
        int ip = Ipv4.parseToInt(trimmed);
        if (ip == Ipv4.INVALID) {
            return null;
        }
        return ParsedEntry.exact(Ipv4.toString(ip), ip);
    }

    private enum EntryType {
        EXACT,
        CIDR,
        RANGE
    }

    private record Range(int start, int end) {
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
        private final IntHashSet exactIps;
        private final int[] starts;
        private final int[] ends;

        private Snapshot(IntHashSet exactIps, int[] starts, int[] ends) {
            this.exactIps = exactIps;
            this.starts = starts;
            this.ends = ends;
        }

        private boolean containsInRange(int ip) {
            int idx = floorUnsigned(starts, ip);
            if (idx < 0) {
                return false;
            }
            return Integer.compareUnsigned(ip, ends[idx]) <= 0;
        }

        private int floorUnsigned(int[] values, int key) {
            int lo = 0;
            int hi = values.length - 1;
            int result = -1;
            while (lo <= hi) {
                int mid = (lo + hi) >>> 1;
                int cmp = Integer.compareUnsigned(values[mid], key);
                if (cmp <= 0) {
                    result = mid;
                    lo = mid + 1;
                } else {
                    hi = mid - 1;
                }
            }
            return result;
        }

        private static Snapshot empty() {
            return new Snapshot(IntHashSet.empty(), new int[0], new int[0]);
        }
    }
}

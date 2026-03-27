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

    public boolean isAllowed(int ipInt) {
        Snapshot s = snapshot;
        return s.exactIps.contains(ipInt) || s.containsInRange(ipInt);
    }

    /**
     * Adds an entry. Returns true on success, false if duplicate, invalid, or store error.
     * Logs a warning with detail when the entry is invalid so operators can diagnose quickly.
     */
    public boolean add(String entry) {
        ParsedEntry parsed = parseEntry(entry);
        if (parsed == null) {
            plugin.getLogger().warning("Invalid IP address or entry format: '" + entry
                    + "' — expected a single IPv4 (e.g. 1.2.3.4), CIDR (1.2.3.0/24), or range (1.2.3.0-1.2.3.255)");
            return false;
        }
        synchronized (writeLock) {
            if (!entries.add(parsed.normalized)) {
                return false; // duplicate
            }
            ParseResult result = parseEntries(entries);
            if (!result.success) {
                entries.remove(parsed.normalized);
                available = false;
                lastError = result.errorMessage;
                plugin.getLogger().warning("Failed to update whitelist after add: " + result.errorMessage);
                return false;
            }
            snapshot = result.snapshot;
            available = true;
            lastError = null;
            save();
            return true;
        }
    }

    /**
     * Removes an entry. Returns true on success, false if not found, invalid, or store error.
     */
    public boolean remove(String entry) {
        ParsedEntry parsed = parseEntry(entry);
        if (parsed == null) {
            plugin.getLogger().warning("Invalid IP address or entry format for removal: '" + entry + "'");
            return false;
        }
        synchronized (writeLock) {
            if (!entries.remove(parsed.normalized)) {
                return false; // not present
            }
            ParseResult result = parseEntries(entries);
            if (!result.success) {
                entries.add(parsed.normalized); // roll back
                available = false;
                lastError = result.errorMessage;
                plugin.getLogger().warning("Failed to update whitelist after remove: " + result.errorMessage);
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

    public boolean isValidEntry(String entry) {
        return parseEntry(entry) != null;
    }

    public boolean contains(String entry) {
        ParsedEntry parsed = parseEntry(entry);
        if (parsed == null) return false;
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
        Set<String> normalized = new HashSet<>();
        List<Range> ranges = new ArrayList<>();
        int exactCount = 0;

        for (String entry : loaded) {
            if (entry == null || entry.isBlank()) continue;
            ParsedEntry parsed = parseEntry(entry);
            if (parsed == null) {
                return ParseResult.failure("Invalid whitelist entry: '" + entry + "'");
            }
            normalized.add(parsed.normalized);
            switch (parsed.type) {
                case EXACT -> exactCount++;
                case CIDR  -> ranges.add(new Range(
                        Ipv4.cidrStart(parsed.singleIp, parsed.prefix),
                        Ipv4.cidrEnd(parsed.singleIp, parsed.prefix)));
                case RANGE -> ranges.add(new Range(parsed.rangeStart, parsed.rangeEnd));
            }
        }

        IntHashSet exactIps = buildExactSet(normalized, exactCount);
        int[][] merged = mergeRanges(ranges);
        return ParseResult.success(normalized, new Snapshot(exactIps, merged[0], merged[1]));
    }

    private IntHashSet buildExactSet(Set<String> normalized, int exactCount) {
        IntHashSet set = new IntHashSet(exactCount);
        for (String entry : normalized) {
            if (entry.indexOf('/') < 0 && entry.indexOf('-') < 0) {
                int ip = Ipv4.parseToInt(entry);
                if (ip != Ipv4.INVALID) set.add(ip);
            }
        }
        return set;
    }

    private int[][] mergeRanges(List<Range> ranges) {
        if (ranges.isEmpty()) return new int[][]{new int[0], new int[0]};

        ranges.sort((a, b) -> {
            int c = Integer.compareUnsigned(a.start, b.start);
            return c != 0 ? c : Integer.compareUnsigned(a.end, b.end);
        });

        List<Range> merged = new ArrayList<>(ranges.size());
        Range cur = ranges.getFirst();
        for (int i = 1; i < ranges.size(); i++) {
            Range next = ranges.get(i);
            if (canMerge(cur, next)) {
                if (Integer.compareUnsigned(next.end, cur.end) > 0) {
                    cur = new Range(cur.start, next.end);
                }
            } else {
                merged.add(cur);
                cur = next;
            }
        }
        merged.add(cur);

        int[] starts = new int[merged.size()];
        int[] ends   = new int[merged.size()];
        for (int i = 0; i < merged.size(); i++) {
            starts[i] = merged.get(i).start;
            ends[i]   = merged.get(i).end;
        }
        return new int[][]{starts, ends};
    }

    private boolean canMerge(Range left, Range right) {
        // Adjacent or overlapping (handles unsigned wrap at 0xFFFFFFFF too)
        if (left.end == 0xFFFFFFFF) return true; // left reaches end of address space
        return Integer.compareUnsigned(right.start, left.end + 1) <= 0;
    }

    private ParsedEntry parseEntry(String raw) {
        if (raw == null) return null;
        String s = raw.trim();
        if (s.isEmpty()) return null;

        int slash = s.indexOf('/');
        int dash  = s.indexOf('-');

        if (slash >= 0 && dash >= 0) return null; // ambiguous

        if (slash >= 0) {
            String[] parts = s.split("/", -1);
            if (parts.length != 2) return null;
            int ip = Ipv4.parseToInt(parts[0]);
            if (ip == Ipv4.INVALID) return null;
            int prefix;
            try { prefix = Integer.parseInt(parts[1]); }
            catch (NumberFormatException e) { return null; }
            if (prefix < 0 || prefix > 32) return null;
            return ParsedEntry.cidr(Ipv4.toString(ip) + "/" + prefix, ip, prefix);
        }

        if (dash >= 0) {
            // Avoid splitting on a leading minus (defensive)
            String[] parts = s.split("-", -1);
            if (parts.length != 2) return null;
            int start = Ipv4.parseToInt(parts[0]);
            int end   = Ipv4.parseToInt(parts[1]);
            if (start == Ipv4.INVALID || end == Ipv4.INVALID) return null;
            if (Integer.compareUnsigned(start, end) > 0) return null;
            return ParsedEntry.range(Ipv4.toString(start) + "-" + Ipv4.toString(end), start, end);
        }

        int ip = Ipv4.parseToInt(s);
        if (ip == Ipv4.INVALID) return null;
        return ParsedEntry.exact(Ipv4.toString(ip), ip);
    }

    // -------------------------------------------------------------------------
    // Internal types
    // -------------------------------------------------------------------------

    private enum EntryType { EXACT, CIDR, RANGE }

    private record Range(int start, int end) {}

    private static final class ParsedEntry {
        final String normalized;
        final EntryType type;
        final int singleIp, prefix, rangeStart, rangeEnd;

        private ParsedEntry(String normalized, EntryType type,
                            int singleIp, int prefix, int rangeStart, int rangeEnd) {
            this.normalized = normalized;
            this.type = type;
            this.singleIp = singleIp;
            this.prefix = prefix;
            this.rangeStart = rangeStart;
            this.rangeEnd = rangeEnd;
        }

        static ParsedEntry exact(String n, int ip) {
            return new ParsedEntry(n, EntryType.EXACT, ip, 0, 0, 0);
        }
        static ParsedEntry cidr(String n, int ip, int prefix) {
            return new ParsedEntry(n, EntryType.CIDR, ip, prefix, 0, 0);
        }
        static ParsedEntry range(String n, int start, int end) {
            return new ParsedEntry(n, EntryType.RANGE, 0, 0, start, end);
        }
    }

    private static final class ParseResult {
        final boolean success;
        final String errorMessage;
        final Set<String> entries;
        final Snapshot snapshot;

        private ParseResult(boolean success, String errorMessage, Set<String> entries, Snapshot snapshot) {
            this.success = success;
            this.errorMessage = errorMessage;
            this.entries = entries;
            this.snapshot = snapshot;
        }

        static ParseResult success(Set<String> entries, Snapshot snapshot) {
            return new ParseResult(true, null, entries, snapshot);
        }
        static ParseResult failure(String msg) {
            return new ParseResult(false, msg, null, null);
        }
    }

    private static final class Snapshot {
        final IntHashSet exactIps;
        final int[] starts, ends;

        Snapshot(IntHashSet exactIps, int[] starts, int[] ends) {
            this.exactIps = exactIps;
            this.starts = starts;
            this.ends = ends;
        }

        boolean containsInRange(int ip) {
            int idx = floorUnsigned(starts, ip);
            return idx >= 0 && Integer.compareUnsigned(ip, ends[idx]) <= 0;
        }

        private static int floorUnsigned(int[] arr, int key) {
            int lo = 0, hi = arr.length - 1, result = -1;
            while (lo <= hi) {
                int mid = (lo + hi) >>> 1;
                if (Integer.compareUnsigned(arr[mid], key) <= 0) {
                    result = mid;
                    lo = mid + 1;
                } else {
                    hi = mid - 1;
                }
            }
            return result;
        }

        static Snapshot empty() {
            return new Snapshot(IntHashSet.empty(), new int[0], new int[0]);
        }
    }
}

package betteripfilter;

import org.bukkit.configuration.file.YamlConfiguration;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.OptionalInt;
import java.util.Set;

public class IpStore {
    private final BetterIpFilterPlugin plugin;
    private final File file;
    private final Object writeLock = new Object();
    private final Set<String> entries = new HashSet<>();
    private final Map<String, String> notes = new HashMap<>();
    private final Map<String, Long> temporaryExpirations = new HashMap<>();
    private volatile Snapshot snapshot = Snapshot.empty();
    private volatile boolean available = true;
    private volatile String lastError;

    public IpStore(BetterIpFilterPlugin plugin) {
        this.plugin = plugin;
        this.file   = new File(plugin.getDataFolder(), "ips.yml");
    }

    public void load() {
        synchronized (writeLock) {
            if (!ensureDataFolder()) return;

            if (!file.exists()) {
                entries.clear();
                notes.clear();
                temporaryExpirations.clear();
                snapshot  = Snapshot.empty();
                available = true;
                lastError = null;
                return;
            }

            YamlConfiguration config = YamlConfiguration.loadConfiguration(file);
            List<String> loaded = config.getStringList("ips");
            ParseResult result  = parseEntries(loaded);
            if (!result.success) {
                setUnavailable("Failed to load ips.yml: " + result.errorMessage);
                return;
            }

            entries.clear();
            entries.addAll(result.entries);
            temporaryExpirations.clear();
            loadNotes(config);
            snapshot  = result.snapshot;
            available = true;
            lastError = null;
        }
    }

    public boolean isAvailable() { return available; }
    public String  getLastError() { return lastError; }

    public boolean isAllowed(int ipInt) {
        cleanupExpiredTemporaryEntries();
        Snapshot s = snapshot;
        return s.exactIps.contains(ipInt) || s.containsInRange(ipInt);
    }

    /**
     * Adds an entry. Returns true on success, false if duplicate, invalid, or store error.
     */
    public boolean add(String entry) {
        ParsedEntry parsed = parseEntry(entry);
        if (parsed == null) {
            plugin.getLogger().warning("Invalid IP/format: '" + entry
                    + "' — expected IPv4 (1.2.3.4), CIDR (1.2.3.0/24), or range (1.2.3.0-1.2.3.255)");
            return false;
        }
        synchronized (writeLock) {
            if (!entries.add(parsed.normalized)) return false; // duplicate
            temporaryExpirations.remove(parsed.normalized);

            ParseResult result = parseEntries(liveEntries());
            if (!result.success) {
                entries.remove(parsed.normalized); // roll back
                setUnavailable("Failed to update whitelist after add: " + result.errorMessage);
                return false;
            }
            commitResult(result);
            save();
            return true;
        }
    }

    public boolean add(String entry, String note) {
        boolean added = add(entry);
        if (added && note != null && !note.isBlank()) {
            setNote(entry, note);
        }
        return added;
    }

    public boolean addTemporary(String entry, long expiresAtMillis, String note) {
        ParsedEntry parsed = parseEntry(entry);
        if (parsed == null || expiresAtMillis <= System.currentTimeMillis()) {
            return false;
        }
        synchronized (writeLock) {
            if (entries.contains(parsed.normalized) || temporaryExpirations.containsKey(parsed.normalized)) return false;

            temporaryExpirations.put(parsed.normalized, expiresAtMillis);
            if (note != null && !note.isBlank()) {
                notes.put(parsed.normalized, sanitizeNote(note));
            }

            ParseResult result = parseEntries(liveEntries());
            if (!result.success) {
                temporaryExpirations.remove(parsed.normalized);
                notes.remove(parsed.normalized);
                setUnavailable("Failed to update whitelist after temporary add: " + result.errorMessage);
                return false;
            }
            commitResult(result);
            return true;
        }
    }

    /**
     * Removes an entry. Returns true on success, false if not found, invalid, or store error.
     */
    public boolean remove(String entry) {
        ParsedEntry parsed = parseEntry(entry);
        if (parsed == null) {
            plugin.getLogger().warning("Invalid IP/format for removal: '" + entry + "'");
            return false;
        }
        synchronized (writeLock) {
            boolean removedPersistent = entries.remove(parsed.normalized);
            boolean removedTemporary = temporaryExpirations.remove(parsed.normalized) != null;
            if (!removedPersistent && !removedTemporary) return false; // not present
            notes.remove(parsed.normalized);

            ParseResult result = parseEntries(liveEntries());
            if (!result.success) {
                if (removedPersistent) entries.add(parsed.normalized); // roll back
                if (removedTemporary) temporaryExpirations.put(parsed.normalized, System.currentTimeMillis() + 1000);
                setUnavailable("Failed to update whitelist after remove: " + result.errorMessage);
                return false;
            }
            commitResult(result);
            save();
            return true;
        }
    }

    public List<String> list() {
        synchronized (writeLock) {
            cleanupExpiredTemporaryEntriesLocked();
            List<String> copy = new ArrayList<>(liveEntries());
            Collections.sort(copy);
            return copy;
        }
    }

    public List<EntryView> listEntries() {
        synchronized (writeLock) {
            cleanupExpiredTemporaryEntriesLocked();
            List<String> sorted = new ArrayList<>(liveEntries());
            Collections.sort(sorted);
            List<EntryView> result = new ArrayList<>(sorted.size());
            for (String entry : sorted) {
                result.add(new EntryView(entry, notes.get(entry), temporaryExpirations.get(entry)));
            }
            return result;
        }
    }

    public boolean isValidEntry(String entry) { return parseEntry(entry) != null; }

    public String normalizeEntry(String entry) {
        ParsedEntry parsed = parseEntry(entry);
        return parsed == null ? null : parsed.normalized;
    }

    public boolean contains(String entry) {
        ParsedEntry parsed = parseEntry(entry);
        if (parsed == null) return false;
        synchronized (writeLock) {
            cleanupExpiredTemporaryEntriesLocked();
            return entries.contains(parsed.normalized) || temporaryExpirations.containsKey(parsed.normalized);
        }
    }

    public CheckResult check(String ip) {
        OptionalInt parsedIp = Ipv4.parse(ip);
        if (parsedIp.isEmpty()) return CheckResult.invalid(ip);
        int ipInt = parsedIp.getAsInt();
        synchronized (writeLock) {
            cleanupExpiredTemporaryEntriesLocked();
            for (String entry : liveEntries()) {
                ParsedEntry parsedEntry = parseEntry(entry);
                if (parsedEntry != null && parsedEntry.matches(ipInt)) {
                    return CheckResult.allowed(Ipv4.toString(ipInt), entry, notes.get(entry), temporaryExpirations.get(entry));
                }
            }
        }
        return CheckResult.denied(Ipv4.toString(ipInt));
    }

    public void setNote(String entry, String note) {
        ParsedEntry parsed = parseEntry(entry);
        if (parsed == null) return;
        synchronized (writeLock) {
            if (!entries.contains(parsed.normalized) && !temporaryExpirations.containsKey(parsed.normalized)) return;
            if (note == null || note.isBlank()) {
                notes.remove(parsed.normalized);
            } else {
                notes.put(parsed.normalized, sanitizeNote(note));
            }
            if (entries.contains(parsed.normalized)) {
                save();
            }
        }
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    /** Applies a successful ParseResult to live state. Must hold writeLock. */
    private void commitResult(ParseResult result) {
        snapshot  = result.snapshot;
        available = true;
        lastError = null;
    }

    /** Marks the store as unavailable and logs. Must hold writeLock. */
    private void setUnavailable(String message) {
        available = false;
        lastError = message;
        plugin.getLogger().warning(message);
    }

    private boolean ensureDataFolder() {
        File folder = plugin.getDataFolder();
        if (!folder.exists() && !folder.mkdirs()) {
            setUnavailable("Failed to create plugin data folder.");
            return false;
        }
        return true;
    }

    private void save() {
        if (!ensureDataFolder()) return;
        YamlConfiguration config = new YamlConfiguration();
        List<String> persistent = new ArrayList<>(entries);
        Collections.sort(persistent);
        config.set("ips", persistent);
        for (String entry : persistent) {
            String note = notes.get(entry);
            if (note != null && !note.isBlank()) {
                config.set("notes." + entry, note);
            }
        }
        try {
            config.save(file);
        } catch (IOException e) {
            plugin.getLogger().severe("Failed to save ips.yml: " + e.getMessage());
        }
    }

    private void loadNotes(YamlConfiguration config) {
        notes.clear();
        if (!config.isConfigurationSection("notes")) return;
        for (String entry : entries) {
            String note = config.getString("notes." + entry);
            if (note != null && !note.isBlank()) {
                notes.put(entry, sanitizeNote(note));
            }
        }
    }

    private Set<String> liveEntries() {
        Set<String> all = new HashSet<>(entries);
        all.addAll(temporaryExpirations.keySet());
        return all;
    }

    private void cleanupExpiredTemporaryEntries() {
        if (temporaryExpirations.isEmpty()) return;
        synchronized (writeLock) {
            cleanupExpiredTemporaryEntriesLocked();
        }
    }

    private void cleanupExpiredTemporaryEntriesLocked() {
        if (temporaryExpirations.isEmpty()) return;
        long now = System.currentTimeMillis();
        boolean changed = temporaryExpirations.entrySet().removeIf(e -> e.getValue() <= now);
        if (!changed) return;

        notes.keySet().removeIf(noteEntry -> !entries.contains(noteEntry) && !temporaryExpirations.containsKey(noteEntry));
        ParseResult result = parseEntries(liveEntries());
        if (result.success) {
            commitResult(result);
        } else {
            setUnavailable("Failed to rebuild whitelist after temporary expiry: " + result.errorMessage);
        }
    }

    private static String sanitizeNote(String note) {
        String trimmed = note.trim();
        return trimmed.length() <= 120 ? trimmed : trimmed.substring(0, 120);
    }

    private ParseResult parseEntries(Iterable<String> loaded) {
        Set<String>  normalized = new HashSet<>();
        List<Range>  ranges     = new ArrayList<>();
        int          exactCount = 0;

        for (String entry : loaded) {
            if (entry == null || entry.isBlank()) continue;
            ParsedEntry parsed = parseEntry(entry);
            if (parsed == null) return ParseResult.failure("Invalid whitelist entry: '" + entry + "'");

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
        int[][]    merged   = mergeRanges(ranges);
        return ParseResult.success(normalized, new Snapshot(exactIps, merged[0], merged[1]));
    }

    private IntHashSet buildExactSet(Set<String> normalized, int exactCount) {
        IntHashSet set = new IntHashSet(exactCount);
        for (String entry : normalized) {
            if (entry.indexOf('/') < 0 && entry.indexOf('-') < 0) {
                Ipv4.parse(entry).ifPresent(set::add);
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
                if (Integer.compareUnsigned(next.end, cur.end) > 0) cur = new Range(cur.start, next.end);
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

    /** Returns true if right is adjacent to or overlaps left. Handles 0xFFFFFFFF edge. */
    private static boolean canMerge(Range left, Range right) {
        if (left.end == 0xFFFFFFFF) return true;
        return Integer.compareUnsigned(right.start, left.end + 1) <= 0;
    }

    private static ParsedEntry parseEntry(String raw) {
        if (raw == null) return null;
        String s = raw.trim();
        if (s.isEmpty()) return null;

        int slash = s.indexOf('/');
        int dash  = s.indexOf('-');
        if (slash >= 0 && dash >= 0) return null; // ambiguous

        if (slash >= 0) {
            String[] parts = s.split("/", -1);
            if (parts.length != 2) return null;
            OptionalInt parsedIp = Ipv4.parse(parts[0]);
            if (parsedIp.isEmpty()) return null;
            int ip = parsedIp.getAsInt();
            int prefix;
            try { prefix = Integer.parseInt(parts[1]); }
            catch (NumberFormatException e) { return null; }
            if (prefix < 0 || prefix > 32) return null;
            return ParsedEntry.cidr(Ipv4.toString(ip) + "/" + prefix, ip, prefix);
        }

        if (dash >= 0) {
            String[] parts = s.split("-", -1);
            if (parts.length != 2) return null;
            OptionalInt parsedStart = Ipv4.parse(parts[0]);
            OptionalInt parsedEnd = Ipv4.parse(parts[1]);
            if (parsedStart.isEmpty() || parsedEnd.isEmpty()) return null;
            int start = parsedStart.getAsInt();
            int end = parsedEnd.getAsInt();
            if (Integer.compareUnsigned(start, end) > 0) return null;
            return ParsedEntry.range(Ipv4.toString(start) + "-" + Ipv4.toString(end), start, end);
        }

        OptionalInt parsedIp = Ipv4.parse(s);
        if (parsedIp.isEmpty()) return null;
        int ip = parsedIp.getAsInt();
        return ParsedEntry.exact(Ipv4.toString(ip), ip);
    }

    // -------------------------------------------------------------------------
    // Internal types
    // -------------------------------------------------------------------------

    private enum EntryType { EXACT, CIDR, RANGE }

    private record Range(int start, int end) {}

    private static final class ParsedEntry {
        final String    normalized;
        final EntryType type;
        final int       singleIp, prefix, rangeStart, rangeEnd;

        private ParsedEntry(String normalized, EntryType type,
                            int singleIp, int prefix, int rangeStart, int rangeEnd) {
            this.normalized = normalized;
            this.type       = type;
            this.singleIp   = singleIp;
            this.prefix     = prefix;
            this.rangeStart = rangeStart;
            this.rangeEnd   = rangeEnd;
        }

        static ParsedEntry exact(String n, int ip)              { return new ParsedEntry(n, EntryType.EXACT, ip, 0, 0, 0); }
        static ParsedEntry cidr(String n, int ip, int prefix)   { return new ParsedEntry(n, EntryType.CIDR, ip, prefix, 0, 0); }
        static ParsedEntry range(String n, int start, int end)  { return new ParsedEntry(n, EntryType.RANGE, 0, 0, start, end); }

        boolean matches(int ip) {
            return switch (type) {
                case EXACT -> singleIp == ip;
                case CIDR -> Integer.compareUnsigned(ip, Ipv4.cidrStart(singleIp, prefix)) >= 0
                        && Integer.compareUnsigned(ip, Ipv4.cidrEnd(singleIp, prefix)) <= 0;
                case RANGE -> Integer.compareUnsigned(ip, rangeStart) >= 0
                        && Integer.compareUnsigned(ip, rangeEnd) <= 0;
            };
        }
    }

    public record EntryView(String value, String note, Long expiresAtMillis) {}

    public record CheckResult(boolean valid, boolean allowed, String ip, String matchedEntry,
                              String note, Long expiresAtMillis) {
        static CheckResult invalid(String ip) {
            return new CheckResult(false, false, ip, null, null, null);
        }

        static CheckResult allowed(String ip, String matchedEntry, String note, Long expiresAtMillis) {
            return new CheckResult(true, true, ip, matchedEntry, note, expiresAtMillis);
        }

        static CheckResult denied(String ip) {
            return new CheckResult(true, false, ip, null, null, null);
        }
    }

    private static final class ParseResult {
        final boolean    success;
        final String     errorMessage;
        final Set<String> entries;
        final Snapshot   snapshot;

        private ParseResult(boolean success, String errorMessage, Set<String> entries, Snapshot snapshot) {
            this.success      = success;
            this.errorMessage = errorMessage;
            this.entries      = entries;
            this.snapshot     = snapshot;
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
        final int[]      starts, ends;

        Snapshot(IntHashSet exactIps, int[] starts, int[] ends) {
            this.exactIps = exactIps;
            this.starts   = starts;
            this.ends     = ends;
        }

        boolean containsInRange(int ip) {
            int idx = floorUnsigned(starts, ip);
            return idx >= 0 && Integer.compareUnsigned(ip, ends[idx]) <= 0;
        }

        private static int floorUnsigned(int[] arr, int key) {
            int lo = 0, hi = arr.length - 1, result = -1;
            while (lo <= hi) {
                int mid = (lo + hi) >>> 1;
                if (Integer.compareUnsigned(arr[mid], key) <= 0) { result = mid; lo = mid + 1; }
                else hi = mid - 1;
            }
            return result;
        }

        static Snapshot empty() {
            return new Snapshot(IntHashSet.empty(), new int[0], new int[0]);
        }
    }
}

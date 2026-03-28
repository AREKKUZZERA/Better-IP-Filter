package betteripfilter;

import java.util.ArrayList;
import java.util.List;

/**
 * Standalone self-test for IP math utilities.
 * Run with: java -cp <jar> betteripfilter.IpMathSelfCheck
 */
public final class IpMathSelfCheck {
    private IpMathSelfCheck() {}

    public static void main(String[] args) {
        runAll();
        System.out.println("IpMathSelfCheck passed");
    }

    public static void runAll() {
        testIpv4ParseRoundTrip();
        testBroadcastIpNotInvalid();
        testCidrRange();
        testMergeRanges();
        testUnsignedBinarySearch();
        testIntHashSetTombstone();
    }

    private static void testIpv4ParseRoundTrip() {
        String ip = "203.0.113.42";
        int parsed = Ipv4.parseToInt(ip);
        assertTrue(parsed != Ipv4.INVALID, "IPv4 parse returned INVALID for " + ip);
        assertTrue(ip.equals(Ipv4.toString(parsed)), "IPv4 roundtrip failed for " + ip);
    }

    /** 255.255.255.255 must NOT be treated as INVALID (old bug: INVALID was -1). */
    private static void testBroadcastIpNotInvalid() {
        int ip = Ipv4.parseToInt("255.255.255.255");
        assertTrue(ip != Ipv4.INVALID, "255.255.255.255 must not be INVALID");
        assertTrue("255.255.255.255".equals(Ipv4.toString(ip)), "255.255.255.255 roundtrip failed");
    }

    private static void testCidrRange() {
        int ip    = Ipv4.parseToInt("10.10.10.66");
        int start = Ipv4.cidrStart(ip, 24);
        int end   = Ipv4.cidrEnd(ip, 24);
        assertTrue("10.10.10.0".equals(Ipv4.toString(start)),   "CIDR start mismatch");
        assertTrue("10.10.10.255".equals(Ipv4.toString(end)),   "CIDR end mismatch");
    }

    private static void testMergeRanges() {
        List<Range> ranges = new ArrayList<>();
        ranges.add(new Range(Ipv4.parseToInt("192.168.0.0"),  Ipv4.parseToInt("192.168.0.10")));
        ranges.add(new Range(Ipv4.parseToInt("192.168.0.11"), Ipv4.parseToInt("192.168.0.20")));
        ranges.add(new Range(Ipv4.parseToInt("192.168.0.15"), Ipv4.parseToInt("192.168.0.30")));

        // Must sort unsigned — IPv4 ints in the high half (≥ 128.x.x.x) are negative in Java.
        ranges.sort((a, b) -> {
            int c = Integer.compareUnsigned(a.start, b.start);
            return c != 0 ? c : Integer.compareUnsigned(a.end, b.end);
        });

        Range merged = ranges.getFirst();
        for (int i = 1; i < ranges.size(); i++) {
            Range next = ranges.get(i);
            if (Integer.compareUnsigned(next.start, merged.end + 1) <= 0) {
                if (Integer.compareUnsigned(next.end, merged.end) > 0) {
                    merged = new Range(merged.start, next.end);
                }
            }
        }
        assertTrue("192.168.0.0" .equals(Ipv4.toString(merged.start)), "Merge start mismatch");
        assertTrue("192.168.0.30".equals(Ipv4.toString(merged.end)),   "Merge end mismatch");
    }

    private static void testUnsignedBinarySearch() {
        int[] starts = {
            Ipv4.parseToInt("1.0.0.0"),
            Ipv4.parseToInt("128.0.0.0"),
            Ipv4.parseToInt("255.255.255.0")
        };
        int idx = floorUnsigned(starts, Ipv4.parseToInt("255.255.255.128"));
        assertTrue(idx == 2, "Unsigned floor index mismatch, got " + idx);
    }

    private static void testIntHashSetTombstone() {
        IntHashSet set = new IntHashSet(8);
        set.add(1);
        set.add(2);
        set.remove(1);
        assertTrue(!set.contains(1), "Removed value should not be present");
        assertTrue( set.contains(2), "Non-removed value must still be present");
        set.add(1);
        assertTrue(set.contains(1), "Re-added value must be present");
    }

    private static int floorUnsigned(int[] values, int key) {
        int lo = 0, hi = values.length - 1, result = -1;
        while (lo <= hi) {
            int mid = (lo + hi) >>> 1;
            if (Integer.compareUnsigned(values[mid], key) <= 0) { result = mid; lo = mid + 1; }
            else hi = mid - 1;
        }
        return result;
    }

    private static void assertTrue(boolean condition, String message) {
        if (!condition) throw new IllegalStateException("FAIL: " + message);
    }

    private record Range(int start, int end) {}
}

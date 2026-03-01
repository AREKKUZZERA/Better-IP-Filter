package betteripfilter;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public final class IpMathSelfCheck {
    private IpMathSelfCheck() {
    }

    public static void main(String[] args) {
        runAll();
        System.out.println("IpMathSelfCheck passed");
    }

    public static void runAll() {
        testIpv4ParseRoundTrip();
        testCidrRange();
        testMergeRanges();
        testUnsignedBinarySearch();
    }

    private static void testIpv4ParseRoundTrip() {
        String ip = "203.0.113.42";
        int parsed = Ipv4.parseToInt(ip);
        assertTrue(parsed != Ipv4.INVALID, "IPv4 parse failed");
        assertTrue(ip.equals(Ipv4.toString(parsed)), "IPv4 roundtrip failed");
    }

    private static void testCidrRange() {
        int ip = Ipv4.parseToInt("10.10.10.66");
        int start = Ipv4.cidrStart(ip, 24);
        int end = Ipv4.cidrEnd(ip, 24);
        assertTrue(Ipv4.toString(start).equals("10.10.10.0"), "CIDR start mismatch");
        assertTrue(Ipv4.toString(end).equals("10.10.10.255"), "CIDR end mismatch");
    }

    private static void testMergeRanges() {
        List<Range> ranges = new ArrayList<>();
        ranges.add(new Range(Ipv4.parseToInt("192.168.0.0"), Ipv4.parseToInt("192.168.0.10")));
        ranges.add(new Range(Ipv4.parseToInt("192.168.0.11"), Ipv4.parseToInt("192.168.0.20")));
        ranges.add(new Range(Ipv4.parseToInt("192.168.0.15"), Ipv4.parseToInt("192.168.0.30")));
        ranges.sort(Comparator.comparingInt(r -> r.start));
        Range merged = ranges.get(0);
        for (int i = 1; i < ranges.size(); i++) {
            Range next = ranges.get(i);
            if (Integer.compareUnsigned(next.start, merged.end + 1) <= 0) {
                if (Integer.compareUnsigned(next.end, merged.end) > 0) {
                    merged = new Range(merged.start, next.end);
                }
            }
        }
        assertTrue(Ipv4.toString(merged.start).equals("192.168.0.0"), "Merge start mismatch");
        assertTrue(Ipv4.toString(merged.end).equals("192.168.0.30"), "Merge end mismatch");
    }

    private static void testUnsignedBinarySearch() {
        int[] starts = {Ipv4.parseToInt("1.0.0.0"), Ipv4.parseToInt("128.0.0.0"), Ipv4.parseToInt("255.255.255.0")};
        int idx = floorUnsigned(starts, Ipv4.parseToInt("255.255.255.128"));
        assertTrue(idx == 2, "Unsigned floor index mismatch");
    }

    private static int floorUnsigned(int[] values, int key) {
        int lo = 0;
        int hi = values.length - 1;
        int result = -1;
        while (lo <= hi) {
            int mid = (lo + hi) >>> 1;
            if (Integer.compareUnsigned(values[mid], key) <= 0) {
                result = mid;
                lo = mid + 1;
            } else {
                hi = mid - 1;
            }
        }
        return result;
    }

    private static void assertTrue(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }

    private record Range(int start, int end) {
    }
}

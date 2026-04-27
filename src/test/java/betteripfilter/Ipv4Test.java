package betteripfilter;

import org.junit.jupiter.api.Test;

import java.util.OptionalInt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Ipv4Test {
    @Test
    void parsesEveryValidIpv4ValueIncludingSignedIntegerBoundaries() {
        assertParsed("0.0.0.0", 0x00000000);
        assertParsed("127.255.255.255", 0x7FFFFFFF);
        assertParsed("128.0.0.0", 0x80000000);
        assertParsed("255.255.255.255", 0xFFFFFFFF);
    }

    @Test
    void rejectsInvalidIpv4ValuesWithoutCollidingWithValidAddresses() {
        assertTrue(Ipv4.parse("256.0.0.1").isEmpty());
        assertTrue(Ipv4.parse("1.2.3").isEmpty());
        assertTrue(Ipv4.parse("1.2.3.4.5").isEmpty());
        assertTrue(Ipv4.parse("1.2.3.-1").isEmpty());
        assertTrue(Ipv4.parse(null).isEmpty());
    }

    @Test
    void cidr16CoversExpectedNetworkBoundaries() {
        int ip = parse("192.168.42.99");

        assertEquals("192.168.0.0", Ipv4.toString(Ipv4.cidrStart(ip, 16)));
        assertEquals("192.168.255.255", Ipv4.toString(Ipv4.cidrEnd(ip, 16)));
        assertInCidr("192.168.0.0", ip, 16);
        assertInCidr("192.168.255.255", ip, 16);
        assertNotInCidr("192.167.255.255", ip, 16);
        assertNotInCidr("192.169.0.0", ip, 16);
    }

    @Test
    void cidr32CoversOnlyExactIp() {
        int ip = parse("203.0.113.42");

        assertEquals("203.0.113.42", Ipv4.toString(Ipv4.cidrStart(ip, 32)));
        assertEquals("203.0.113.42", Ipv4.toString(Ipv4.cidrEnd(ip, 32)));
        assertInCidr("203.0.113.42", ip, 32);
        assertNotInCidr("203.0.113.41", ip, 32);
        assertNotInCidr("203.0.113.43", ip, 32);
    }

    @Test
    void cidr0CoversWholeIpv4Space() {
        int ip = parse("203.0.113.42");

        assertEquals("0.0.0.0", Ipv4.toString(Ipv4.cidrStart(ip, 0)));
        assertEquals("255.255.255.255", Ipv4.toString(Ipv4.cidrEnd(ip, 0)));
        assertInCidr("0.0.0.0", ip, 0);
        assertInCidr("128.0.0.0", ip, 0);
        assertInCidr("255.255.255.255", ip, 0);
    }

    @Test
    void cidrMathWorksForUnsignedIpv4Values() {
        int ip = parse("200.10.20.30");

        assertEquals("200.10.0.0", Ipv4.toString(Ipv4.cidrStart(ip, 16)));
        assertEquals("200.10.255.255", Ipv4.toString(Ipv4.cidrEnd(ip, 16)));
        assertInCidr("200.10.200.1", ip, 16);
        assertNotInCidr("200.11.0.1", ip, 16);
    }

    private static void assertParsed(String value, int expected) {
        OptionalInt parsed = Ipv4.parse(value);
        assertTrue(parsed.isPresent(), value + " should parse");
        assertEquals(expected, parsed.getAsInt());
        assertEquals(value, Ipv4.toString(parsed.getAsInt()));
    }

    private static int parse(String value) {
        return Ipv4.parse(value).orElseThrow();
    }

    private static void assertInCidr(String candidate, int networkIp, int prefix) {
        int value = parse(candidate);
        assertTrue(isInCidr(value, networkIp, prefix), candidate + " should be inside /" + prefix);
    }

    private static void assertNotInCidr(String candidate, int networkIp, int prefix) {
        int value = parse(candidate);
        assertTrue(!isInCidr(value, networkIp, prefix), candidate + " should be outside /" + prefix);
    }

    private static boolean isInCidr(int value, int networkIp, int prefix) {
        int start = Ipv4.cidrStart(networkIp, prefix);
        int end = Ipv4.cidrEnd(networkIp, prefix);
        return Integer.compareUnsigned(value, start) >= 0
                && Integer.compareUnsigned(value, end) <= 0;
    }
}

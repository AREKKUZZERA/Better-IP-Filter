package betteripfilter;

import java.net.InetAddress;

public final class Ipv4 {
    private Ipv4() {}

    /**
     * Sentinel value returned when parsing fails.
     * Uses Integer.MIN_VALUE (0x80000000) — not a valid IPv4 address in our context,
     * since 128.0.0.0 is represented as 0x80000000 but we never use MIN_VALUE elsewhere.
     *
     * NOTE: We deliberately avoid -1 (0xFFFFFFFF) because that is a real IPv4 address:
     * 255.255.255.255, which would cause false "invalid" results for that IP.
     */
    public static final int INVALID = Integer.MIN_VALUE;

    /**
     * Parses a dotted-decimal IPv4 string to a 32-bit int.
     * Returns INVALID on any error.
     */
    public static int parseToInt(String value) {
        if (value == null) return INVALID;
        String s = value.trim();
        int len = s.length();
        // min "0.0.0.0" = 7, max "255.255.255.255" = 15
        if (len < 7 || len > 15) return INVALID;

        int result = 0;
        int octet = 0;
        int octetLen = 0;
        int dots = 0;

        for (int i = 0; i < len; i++) {
            char ch = s.charAt(i);
            if (ch == '.') {
                if (octetLen == 0 || dots == 3) return INVALID;
                result = (result << 8) | octet;
                dots++;
                octet = 0;
                octetLen = 0;
            } else if (ch >= '0' && ch <= '9') {
                octet = octet * 10 + (ch - '0');
                if (octet > 255) return INVALID;
                octetLen++;
            } else {
                return INVALID;
            }
        }

        if (octetLen == 0 || dots != 3) return INVALID;
        return (result << 8) | octet;
    }

    public static int fromInetAddress(InetAddress address) {
        if (address == null) return INVALID;
        byte[] raw = address.getAddress();
        if (raw.length != 4) return INVALID;
        return ((raw[0] & 0xFF) << 24)
             | ((raw[1] & 0xFF) << 16)
             | ((raw[2] & 0xFF) << 8)
             |  (raw[3] & 0xFF);
    }

    public static String toString(int value) {
        return ((value >>> 24) & 0xFF) + "."
             + ((value >>> 16) & 0xFF) + "."
             + ((value >>>  8) & 0xFF) + "."
             +  (value         & 0xFF);
    }

    public static int cidrStart(int ip, int prefix) {
        int mask = (prefix == 0) ? 0 : (-1 << (32 - prefix));
        return ip & mask;
    }

    public static int cidrEnd(int ip, int prefix) {
        int mask = (prefix == 0) ? 0 : (-1 << (32 - prefix));
        return (ip & mask) | ~mask;
    }
}

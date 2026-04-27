package betteripfilter;

import java.net.InetAddress;
import java.util.OptionalInt;

public final class Ipv4 {
    private Ipv4() {}

    /** Legacy sentinel. New code should use parse()/fromInetAddressOptional(). */
    public static final int INVALID = Integer.MIN_VALUE;

    public static OptionalInt parse(String value) {
        if (value == null) return OptionalInt.empty();
        String s = value.trim();
        int len = s.length();
        if (len < 7 || len > 15) return OptionalInt.empty();

        int result = 0;
        int octet = 0;
        int octetLen = 0;
        int dots = 0;

        for (int i = 0; i < len; i++) {
            char ch = s.charAt(i);
            if (ch == '.') {
                if (octetLen == 0 || dots == 3) return OptionalInt.empty();
                result = (result << 8) | octet;
                dots++;
                octet = 0;
                octetLen = 0;
            } else if (ch >= '0' && ch <= '9') {
                octet = octet * 10 + (ch - '0');
                if (octet > 255) return OptionalInt.empty();
                octetLen++;
            } else {
                return OptionalInt.empty();
            }
        }

        if (octetLen == 0 || dots != 3) return OptionalInt.empty();
        return OptionalInt.of((result << 8) | octet);
    }

    /**
     * Legacy parser retained for compatibility. It cannot represent every valid
     * IPv4 address plus invalid input without collisions; prefer parse(String).
     */
    public static int parseToInt(String value) {
        return parse(value).orElse(INVALID);
    }

    public static OptionalInt fromInetAddressOptional(InetAddress address) {
        if (address == null) return OptionalInt.empty();
        byte[] raw = address.getAddress();
        if (raw.length != 4) return OptionalInt.empty();
        return OptionalInt.of(((raw[0] & 0xFF) << 24)
                | ((raw[1] & 0xFF) << 16)
                | ((raw[2] & 0xFF) << 8)
                |  (raw[3] & 0xFF));
    }

    public static int fromInetAddress(InetAddress address) {
        return fromInetAddressOptional(address).orElse(INVALID);
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

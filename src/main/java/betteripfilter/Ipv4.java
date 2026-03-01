package betteripfilter;

import java.net.InetAddress;

public final class Ipv4 {
    private Ipv4() {
    }

    public static final int INVALID = -1;

    public static int parseToInt(String value) {
        if (value == null) {
            return INVALID;
        }
        String trimmed = value.trim();
        int length = trimmed.length();
        if (length < 7 || length > 15) {
            return INVALID;
        }
        int result = 0;
        int part = 0;
        int partLength = 0;
        int parts = 0;
        for (int i = 0; i < length; i++) {
            char ch = trimmed.charAt(i);
            if (ch == '.') {
                if (partLength == 0) {
                    return INVALID;
                }
                result = (result << 8) | part;
                parts++;
                part = 0;
                partLength = 0;
                continue;
            }
            if (ch < '0' || ch > '9') {
                return INVALID;
            }
            part = part * 10 + (ch - '0');
            partLength++;
            if (part > 255) {
                return INVALID;
            }
        }
        if (partLength == 0) {
            return INVALID;
        }
        result = (result << 8) | part;
        parts++;
        if (parts != 4) {
            return INVALID;
        }
        return result;
    }

    public static int fromInetAddress(InetAddress address) {
        if (address == null) {
            return INVALID;
        }
        byte[] raw = address.getAddress();
        if (raw.length != 4) {
            return INVALID;
        }
        return ((raw[0] & 0xFF) << 24)
                | ((raw[1] & 0xFF) << 16)
                | ((raw[2] & 0xFF) << 8)
                | (raw[3] & 0xFF);
    }

    public static String toString(int value) {
        return (value >>> 24 & 0xFF) + "."
                + (value >>> 16 & 0xFF) + "."
                + (value >>> 8 & 0xFF) + "."
                + (value & 0xFF);
    }

    public static int cidrStart(int ip, int prefix) {
        int mask = prefix == 0 ? 0 : -1 << (32 - prefix);
        return ip & mask;
    }

    public static int cidrEnd(int ip, int prefix) {
        int mask = prefix == 0 ? 0 : -1 << (32 - prefix);
        return (ip & mask) | ~mask;
    }
}

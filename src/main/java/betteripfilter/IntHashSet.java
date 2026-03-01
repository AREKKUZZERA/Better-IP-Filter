package betteripfilter;

import java.util.Arrays;

public final class IntHashSet {
    private static final int EMPTY = 0;
    private static final int OCCUPIED = 1;

    private final int[] keys;
    private final byte[] states;
    private final int mask;

    public IntHashSet(int expectedSize) {
        int capacity = 1;
        int min = Math.max(4, expectedSize * 2);
        while (capacity < min) {
            capacity <<= 1;
        }
        this.keys = new int[capacity];
        this.states = new byte[capacity];
        this.mask = capacity - 1;
    }

    public void add(int value) {
        int index = mix(value) & mask;
        while (states[index] == OCCUPIED) {
            if (keys[index] == value) {
                return;
            }
            index = (index + 1) & mask;
        }
        keys[index] = value;
        states[index] = OCCUPIED;
    }

    public boolean contains(int value) {
        int index = mix(value) & mask;
        while (states[index] != EMPTY) {
            if (states[index] == OCCUPIED && keys[index] == value) {
                return true;
            }
            index = (index + 1) & mask;
        }
        return false;
    }

    private int mix(int value) {
        int h = value * 0x9E3779B9;
        return h ^ (h >>> 16);
    }

    public static IntHashSet empty() {
        return new IntHashSet(0);
    }

    @Override
    public String toString() {
        return "IntHashSet{" +
                "keys=" + Arrays.toString(keys) +
                '}';
    }
}

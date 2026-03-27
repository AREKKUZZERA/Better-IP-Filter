package betteripfilter;

/**
 * Compact open-addressing int hash set.
 * Uses a tombstone byte to support deletion without breaking probe chains.
 */
public final class IntHashSet {
    private static final byte EMPTY    = 0;
    private static final byte OCCUPIED = 1;
    private static final byte DELETED  = 2;

    private final int[]  keys;
    private final byte[] states;
    private final int    mask;

    public IntHashSet(int expectedSize) {
        int capacity = 4;
        int min = Math.max(4, expectedSize * 2);
        while (capacity < min) capacity <<= 1;
        this.keys   = new int[capacity];
        this.states = new byte[capacity];
        this.mask   = capacity - 1;
    }

    public void add(int value) {
        int index = mix(value) & mask;
        int firstDeleted = -1;
        while (states[index] != EMPTY) {
            if (states[index] == OCCUPIED && keys[index] == value) return; // already present
            if (states[index] == DELETED && firstDeleted < 0) firstDeleted = index;
            index = (index + 1) & mask;
        }
        int insertAt = (firstDeleted >= 0) ? firstDeleted : index;
        keys[insertAt]   = value;
        states[insertAt] = OCCUPIED;
    }

    public boolean contains(int value) {
        int index = mix(value) & mask;
        while (states[index] != EMPTY) {
            if (states[index] == OCCUPIED && keys[index] == value) return true;
            index = (index + 1) & mask;
        }
        return false;
    }

    public void remove(int value) {
        int index = mix(value) & mask;
        while (states[index] != EMPTY) {
            if (states[index] == OCCUPIED && keys[index] == value) {
                states[index] = DELETED;
                return;
            }
            index = (index + 1) & mask;
        }
    }

    private static int mix(int value) {
        int h = value * 0x9E3779B9;
        return h ^ (h >>> 16);
    }

    public static IntHashSet empty() {
        return new IntHashSet(0);
    }
}

package betteripfilter;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

public class RateLimiter {
    private static final int CLEANUP_CHECK_INTERVAL = 64;
    private final ConcurrentHashMap<Integer, AttemptBucket> buckets = new ConcurrentHashMap<>();
    private final int cleanupThreshold;
    private final AtomicInteger cleanupCounter = new AtomicInteger();

    public RateLimiter(int cleanupThreshold) {
        this.cleanupThreshold = cleanupThreshold;
    }

    public boolean tryAcquire(String key, long windowMillis, int maxAttempts) {
        int parsed = Ipv4.parseToInt(key);
        if (parsed == Ipv4.INVALID) {
            return false;
        }
        return tryAcquire(parsed, windowMillis, maxAttempts);
    }

    public boolean tryAcquire(int key, long windowMillis, int maxAttempts) {
        long now = System.currentTimeMillis();
        AttemptBucket bucket = buckets.compute(key, (ignored, existing) -> {
            if (existing == null) {
                return new AttemptBucket(now, 1);
            }
            if (now - existing.windowStart >= windowMillis) {
                existing.windowStart = now;
                existing.count = 1;
                return existing;
            }
            existing.count++;
            return existing;
        });

        boolean allowed = bucket.count <= maxAttempts;
        if (buckets.size() > cleanupThreshold && cleanupCounter.incrementAndGet() % CLEANUP_CHECK_INTERVAL == 0) {
            cleanup(now, windowMillis);
        }
        return allowed;
    }

    private void cleanup(long now, long windowMillis) {
        long expiry = windowMillis * 2;
        buckets.entrySet().removeIf(entry -> now - entry.getValue().windowStart >= expiry);
    }

    private static final class AttemptBucket {
        private volatile long windowStart;
        private volatile int count;

        private AttemptBucket(long windowStart, int count) {
            this.windowStart = windowStart;
            this.count = count;
        }
    }
}

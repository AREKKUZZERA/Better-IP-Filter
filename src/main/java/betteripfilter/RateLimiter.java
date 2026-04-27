package betteripfilter;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Sliding-window rate limiter keyed by IPv4 int.
 *
 * <p>Thread-safety: each bucket is updated inside ConcurrentHashMap.compute(),
 * which holds the segment lock for that key — so windowStart + count are
 * always mutated together without a separate volatile race.
 */
public class RateLimiter {
    private static final int CLEANUP_CHECK_INTERVAL = 64;

    private final ConcurrentHashMap<Integer, AttemptBucket> buckets = new ConcurrentHashMap<>();
    private final int cleanupThreshold;
    private final AtomicInteger cleanupCounter = new AtomicInteger();

    public RateLimiter(int cleanupThreshold) {
        this.cleanupThreshold = cleanupThreshold;
    }

    /** Convenience overload that parses an IP string first. */
    public boolean tryAcquire(String key, long windowMillis, int maxAttempts) {
        return Ipv4.parse(key)
                .stream()
                .anyMatch(parsed -> tryAcquire(parsed, windowMillis, maxAttempts));
    }

    public boolean tryAcquire(int key, long windowMillis, int maxAttempts) {
        long now = System.currentTimeMillis();

        // compute() holds the bucket lock — windowStart + count updated atomically.
        AttemptBucket bucket = buckets.compute(key, (ignored, existing) -> {
            if (existing == null) return new AttemptBucket(now, 1);
            if (now - existing.windowStart >= windowMillis) {
                existing.windowStart = now;
                existing.count = 1;
            } else {
                existing.count++;
            }
            return existing;
        });

        boolean allowed = bucket.count <= maxAttempts;

        if (buckets.size() > cleanupThreshold
                && cleanupCounter.incrementAndGet() % CLEANUP_CHECK_INTERVAL == 0) {
            cleanup(now, windowMillis);
        }
        return allowed;
    }

    private void cleanup(long now, long windowMillis) {
        long expiry = windowMillis * 2;
        buckets.entrySet().removeIf(e -> now - e.getValue().windowStart >= expiry);
    }

    /** Not volatile — fields are only ever mutated inside ConcurrentHashMap.compute(). */
    private static final class AttemptBucket {
        long windowStart;
        int  count;

        AttemptBucket(long windowStart, int count) {
            this.windowStart = windowStart;
            this.count = count;
        }
    }
}

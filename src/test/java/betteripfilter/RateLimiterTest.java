package betteripfilter;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RateLimiterTest {
    @Test
    void stringKeysSupportIpv4AddressesWhoseIntegerValueMatchesOldInvalidSentinel() {
        RateLimiter limiter = new RateLimiter(100);

        assertTrue(limiter.tryAcquire("128.0.0.0", 1_000, 1));
        assertFalse(limiter.tryAcquire("128.0.0.0", 1_000, 1));
    }
}

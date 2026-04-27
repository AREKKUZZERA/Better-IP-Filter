package betteripfilter;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import java.util.logging.Logger;

public class WebhookNotifier {
    private static final int CLEANUP_THRESHOLD = 2048;

    private final HttpClient client;
    private final Logger logger;
    private final ArrayBlockingQueue<WebhookJob> queue;
    private final RateLimiter limiter;
    private final int perSecondLimit;
    private final AtomicLong droppedByRateLimit = new AtomicLong();
    private final AtomicLong droppedByQueue     = new AtomicLong();
    private final long statLogIntervalMillis;
    // Guarded by itself — only the worker thread writes after construction.
    private long lastStatLogMillis;
    private volatile boolean running = true;
    private final Thread worker;

    public WebhookNotifier(Logger logger, int queueSize, int perSecondLimit, long statLogIntervalMillis) {
        this.logger               = logger;
        this.client               = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();
        this.queue                = new ArrayBlockingQueue<>(Math.max(1, queueSize));
        this.perSecondLimit       = Math.max(1, perSecondLimit);
        this.statLogIntervalMillis = Math.max(1000, statLogIntervalMillis);
        this.lastStatLogMillis    = System.currentTimeMillis();
        this.limiter              = new RateLimiter(CLEANUP_THRESHOLD);
        this.worker               = new Thread(this::runLoop, "BetterIPF-Webhook");
        this.worker.setDaemon(true);
        this.worker.start();
    }

    public void send(String url, int timeoutMs, DenyReason reason, String name, String ip) {
        if (!running || !isValidWebhookUrl(url)) return;

        if (!limiter.tryAcquire(0, 1000, perSecondLimit)) {
            droppedByRateLimit.incrementAndGet();
            return;
        }
        if (!queue.offer(new WebhookJob(url, timeoutMs, reason, name, ip))) {
            droppedByQueue.incrementAndGet();
        }
    }

    private void runLoop() {
        while (running || !queue.isEmpty()) {
            try {
                WebhookJob job = queue.poll(100, TimeUnit.MILLISECONDS);
                if (job != null) sendNow(job);
                maybeLogDropStats();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                running = false;
            }
        }
        maybeLogDropStats();
    }

    private void sendNow(WebhookJob job) {
        String payload = buildPayload(job.reason, job.name, job.ip);
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(job.url))
                .timeout(Duration.ofMillis(job.timeoutMs))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(payload))
                .build();

        client.sendAsync(request, HttpResponse.BodyHandlers.discarding())
                .exceptionally(ex -> {
                    logger.log(Level.FINE, "Failed to send webhook notification", ex);
                    return null;
                });
    }

    static boolean isValidWebhookUrl(String value) {
        if (value == null || value.isBlank()) return false;
        try {
            URI uri = URI.create(value);
            String scheme = uri.getScheme();
            return ("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme))
                    && uri.getHost() != null
                    && !uri.getHost().isBlank();
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    public void shutdown(long timeoutMillis) {
        running = false;
        worker.interrupt();
        try {
            worker.join(Math.max(100, timeoutMillis));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        maybeLogDropStats();
    }

    /** Called only from the worker thread — no synchronization needed on lastStatLogMillis. */
    private void maybeLogDropStats() {
        long now = System.currentTimeMillis();
        if (now - lastStatLogMillis < statLogIntervalMillis) return;

        long rate  = droppedByRateLimit.getAndSet(0);
        long queue = droppedByQueue.getAndSet(0);
        if (rate > 0 || queue > 0) {
            logger.fine("Webhook drops in last interval: rateLimit=" + rate + ", queueFull=" + queue);
        }
        lastStatLogMillis = now;
    }

    private String buildPayload(DenyReason reason, String name, String ip) {
        String safeName = Objects.requireNonNullElse(name, "");
        String safeIp   = Objects.requireNonNullElse(ip,   "");
        return "{" +
                "\"plugin\":\"Better-IP-Filter\"," +
                "\"reason\":\"" + reason.name() + "\"," +
                "\"name\":\""   + escapeJson(safeName) + "\"," +
                "\"ip\":\""     + escapeJson(safeIp)   + "\"," +
                "\"time\":\""   + Instant.now()         + "\"" +
                "}";
    }

    private static String escapeJson(String value) {
        StringBuilder sb = new StringBuilder(value.length() + 16);
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            switch (ch) {
                case '"'  -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default   -> sb.append(ch);
            }
        }
        return sb.toString();
    }

    private record WebhookJob(String url, int timeoutMs, DenyReason reason, String name, String ip) {}
}

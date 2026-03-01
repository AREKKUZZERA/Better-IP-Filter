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
    private final AtomicLong droppedByQueue = new AtomicLong();
    private final long statLogIntervalMillis;
    private volatile long lastStatLogMillis = System.currentTimeMillis();
    private volatile boolean running = true;
    private final Thread worker;

    public WebhookNotifier(Logger logger, int queueSize, int perSecondLimit, long statLogIntervalMillis) {
        this.logger = logger;
        this.client = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .build();
        this.queue = new ArrayBlockingQueue<>(Math.max(1, queueSize));
        this.perSecondLimit = Math.max(1, perSecondLimit);
        this.statLogIntervalMillis = Math.max(1000, statLogIntervalMillis);
        this.limiter = new RateLimiter(CLEANUP_THRESHOLD);
        this.worker = new Thread(this::runLoop, "BetterIPF-Webhook");
        this.worker.setDaemon(true);
        this.worker.start();
    }

    public void send(String url, int timeoutMs, DenyReason reason, String name, String ip) {
        if (url == null || url.isBlank() || !running) {
            return;
        }
        if (!limiter.tryAcquire(0, 1000, perSecondLimit)) {
            droppedByRateLimit.incrementAndGet();
            maybeLogDropStats();
            return;
        }
        WebhookJob job = new WebhookJob(url, timeoutMs, reason, name, ip);
        if (!queue.offer(job)) {
            droppedByQueue.incrementAndGet();
            maybeLogDropStats();
        }
    }

    private void runLoop() {
        while (running || !queue.isEmpty()) {
            try {
                WebhookJob job = queue.poll(100, TimeUnit.MILLISECONDS);
                if (job != null) {
                    sendNow(job);
                }
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

    private void maybeLogDropStats() {
        long now = System.currentTimeMillis();
        if (now - lastStatLogMillis < statLogIntervalMillis) {
            return;
        }
        long rate = droppedByRateLimit.getAndSet(0);
        long queueDrops = droppedByQueue.getAndSet(0);
        if (rate > 0 || queueDrops > 0) {
            logger.fine("Webhook drops in last interval: rateLimit=" + rate + ", queueFull=" + queueDrops);
        }
        lastStatLogMillis = now;
    }

    private String buildPayload(DenyReason reason, String name, String ip) {
        String safeName = Objects.requireNonNullElse(name, "");
        String safeIp = Objects.requireNonNullElse(ip, "");
        String time = Instant.now().toString();
        return new StringBuilder(200)
                .append('{')
                .append("\"plugin\":\"Better-IP-Filter\",")
                .append("\"reason\":\"").append(reason.name()).append("\",")
                .append("\"name\":\"").append(escapeJson(safeName)).append("\",")
                .append("\"ip\":\"").append(escapeJson(safeIp)).append("\",")
                .append("\"time\":\"").append(time).append("\"")
                .append('}')
                .toString();
    }

    private String escapeJson(String value) {
        StringBuilder builder = new StringBuilder(value.length() + 16);
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (ch == '"' || ch == '\\') {
                builder.append('\\').append(ch);
            } else if (ch == '\n') {
                builder.append("\\n");
            } else if (ch == '\r') {
                builder.append("\\r");
            } else if (ch == '\t') {
                builder.append("\\t");
            } else {
                builder.append(ch);
            }
        }
        return builder.toString();
    }

    private record WebhookJob(String url, int timeoutMs, DenyReason reason, String name, String ip) {
    }
}

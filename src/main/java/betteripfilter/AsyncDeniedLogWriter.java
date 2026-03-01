package betteripfilter;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Logger;

public class AsyncDeniedLogWriter {
    private final Logger logger;
    private final Path logFile;
    private final ArrayBlockingQueue<String> queue;
    private final Thread worker;
    private final int batchSize;
    private final long flushIntervalMillis;
    private final long dropLogIntervalMillis;
    private final AtomicLong dropped = new AtomicLong();
    private volatile boolean running = true;
    private volatile long lastDropLogMillis = System.currentTimeMillis();

    public AsyncDeniedLogWriter(Logger logger, Path logFile, int queueSize, int batchSize,
                                long flushIntervalMillis, Duration dropLogInterval) {
        this.logger = logger;
        this.logFile = logFile;
        this.queue = new ArrayBlockingQueue<>(Math.max(1, queueSize));
        this.batchSize = Math.max(1, batchSize);
        this.flushIntervalMillis = Math.max(100, flushIntervalMillis);
        this.dropLogIntervalMillis = Math.max(1000, dropLogInterval.toMillis());
        this.worker = new Thread(this::runLoop, "BetterIPF-DeniedLog");
        this.worker.setDaemon(true);
        this.worker.start();
    }

    public void enqueue(String line) {
        if (!running) {
            return;
        }
        if (!queue.offer(line)) {
            dropped.incrementAndGet();
            maybeLogDrop();
        }
    }

    private void runLoop() {
        List<String> batch = new ArrayList<>(batchSize);
        long lastFlush = System.currentTimeMillis();

        while (running || !queue.isEmpty()) {
            try {
                String line = queue.poll(100, TimeUnit.MILLISECONDS);
                if (line != null) {
                    batch.add(line);
                }

                long now = System.currentTimeMillis();
                boolean intervalPassed = now - lastFlush >= flushIntervalMillis;
                if (!batch.isEmpty() && (batch.size() >= batchSize || intervalPassed || (!running && queue.isEmpty()))) {
                    writeBatch(batch);
                    batch.clear();
                    lastFlush = now;
                }
                maybeLogDrop();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                running = false;
            }
        }

        if (!batch.isEmpty()) {
            writeBatch(batch);
        }
    }

    private void writeBatch(List<String> batch) {
        try {
            Files.createDirectories(logFile.getParent());
            try (BufferedWriter writer = Files.newBufferedWriter(logFile,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND)) {
                for (String line : batch) {
                    writer.write(line);
                    writer.newLine();
                }
                writer.flush();
            }
        } catch (IOException e) {
            logger.warning("Failed to write denied log batch: " + e.getMessage());
        }
    }

    private void maybeLogDrop() {
        long now = System.currentTimeMillis();
        if (now - lastDropLogMillis < dropLogIntervalMillis) {
            return;
        }
        long droppedCount = dropped.getAndSet(0);
        if (droppedCount > 0) {
            logger.warning("Dropped " + droppedCount + " denied log lines due to full queue at " + Instant.now());
        }
        lastDropLogMillis = now;
    }

    public void shutdown(long timeoutMillis) {
        running = false;
        worker.interrupt();
        try {
            worker.join(Math.max(100, timeoutMillis));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        maybeLogDrop();
    }
}

package betteripfilter;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

public class WebhookNotifier {
    private final HttpClient client;
    private final Logger logger;

    public WebhookNotifier(Logger logger) {
        this.logger = logger;
        this.client = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .build();
    }

    public void send(String url, int timeoutMs, DenyReason reason, String name, String ip) {
        if (url == null || url.isBlank()) {
            return;
        }
        String payload = buildPayload(reason, name, ip);
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .timeout(Duration.ofMillis(timeoutMs))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(payload))
            .build();

        client.sendAsync(request, HttpResponse.BodyHandlers.discarding())
            .exceptionally(ex -> {
                logger.log(Level.FINE, "Failed to send webhook notification", ex);
                return null;
            });
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
}

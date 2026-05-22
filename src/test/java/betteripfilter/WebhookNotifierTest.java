package betteripfilter;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class WebhookNotifierTest {
    @Test
    void acceptsOnlyHttpAndHttpsWebhookUrls() {
        assertTrue(WebhookNotifier.isValidWebhookUrl("https://example.com/hook"));
        assertTrue(WebhookNotifier.isValidWebhookUrl("http://127.0.0.1:8080/hook", true));

        assertFalse(WebhookNotifier.isValidWebhookUrl(""));
        assertFalse(WebhookNotifier.isValidWebhookUrl("not a url"));
        assertFalse(WebhookNotifier.isValidWebhookUrl("ftp://example.com/hook"));
        assertFalse(WebhookNotifier.isValidWebhookUrl("file:///etc/passwd"));
        assertFalse(WebhookNotifier.isValidWebhookUrl("http://127.0.0.1:8080/hook"));
        assertFalse(WebhookNotifier.isValidWebhookUrl("http://192.168.1.10/hook"));
        assertFalse(WebhookNotifier.isValidWebhookUrl("http://localhost/hook"));
    }
}

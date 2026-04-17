package org.mazhai.central.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * SIEM & Observability Integration Forwarding Service.
 * Runs on Java 21 Virtual Threads for near-zero latency forwarding.
 * Formats Aran threat telemetry into vendor-native formats and pushes in real-time.
 */
@Service
public class IntegrationForwardingService {

    private static final Logger log = LoggerFactory.getLogger(IntegrationForwardingService.class);

    /** Virtual thread executor — scales to millions of concurrent forwards without blocking */
    private final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();

    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    /** Active integrations: key = integration id, value = config */
    private final Map<String, SiemConfig> activeIntegrations = new ConcurrentHashMap<>();

    public void registerIntegration(String id, String name, String webhookUrl, String apiKey) {
        activeIntegrations.put(id, new SiemConfig(id, name, webhookUrl, apiKey));
        log.info("SIEM integration registered: {} -> {}", name, webhookUrl);
    }

    public void removeIntegration(String id) {
        var removed = activeIntegrations.remove(id);
        if (removed != null) {
            log.info("SIEM integration removed: {}", removed.name());
        }
    }

    /**
     * Forward a threat event to ALL active SIEM integrations.
     * Each forward runs on its own virtual thread — non-blocking, massively parallel.
     */
    public void forwardThreatEvent(ThreatEvent event) {
        for (var config : activeIntegrations.values()) {
            executor.submit(() -> {
                try {
                    String payload = formatForVendor(config, event);
                    var request = HttpRequest.newBuilder()
                            .uri(URI.create(config.webhookUrl()))
                            .header("Content-Type", "application/json")
                            .header("Authorization", "Bearer " + config.apiKey())
                            .timeout(Duration.ofSeconds(10))
                            .POST(HttpRequest.BodyPublishers.ofString(payload))
                            .build();

                    var response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

                    if (response.statusCode() >= 200 && response.statusCode() < 300) {
                        log.debug("Forwarded to {}: HTTP {}", config.name(), response.statusCode());
                    } else {
                        log.warn("SIEM forward failed for {}: HTTP {} — {}", config.name(), response.statusCode(), response.body());
                    }
                } catch (Exception e) {
                    log.error("SIEM forward error for {}: {}", config.name(), e.getMessage());
                }
            });
        }
    }

    /**
     * Format telemetry into vendor-native format.
     * Splunk: HEC JSON, Datadog: Logs API, QRadar: CEF, Elastic: ECS.
     */
    private String formatForVendor(SiemConfig config, ThreatEvent event) {
        return switch (config.id()) {
            case "splunk" -> formatSplunkHEC(event);
            case "datadog" -> formatDatadogLog(event);
            case "qradar" -> formatQRadarCEF(event);
            case "elastic" -> formatElasticECS(event);
            default -> formatGenericJSON(event);
        };
    }

    private String formatSplunkHEC(ThreatEvent event) {
        return """
                {"event":{"type":"%s","severity":"%s","device":"%s","action":"%s","timestamp":"%s","sdk":"aran-rasp"},"sourcetype":"aran:threat","source":"aran-sdk"}
                """.formatted(event.type(), event.severity(), event.device(), event.action(), event.timestamp()).trim();
    }

    private String formatDatadogLog(ThreatEvent event) {
        return """
                {"ddsource":"aran-rasp","ddtags":"env:production,service:aran","hostname":"%s","message":"[%s] %s on %s — Action: %s","level":"%s","timestamp":"%s"}
                """.formatted(event.device(), event.severity(), event.type(), event.device(), event.action(),
                event.severity().equalsIgnoreCase("Critical") ? "error" : "warn", event.timestamp()).trim();
    }

    private String formatQRadarCEF(ThreatEvent event) {
        int cefSev = switch (event.severity()) {
            case "Critical" -> 10;
            case "High" -> 7;
            case "Medium" -> 4;
            default -> 1;
        };
        return """
                CEF:0|Mazhai|AranRASP|1.0|%s|%s|%d|src=%s act=%s rt=%s
                """.formatted(event.type().replace(" ", "_"), event.type(), cefSev, event.device(), event.action(), event.timestamp()).trim();
    }

    private String formatElasticECS(ThreatEvent event) {
        return """
                {"@timestamp":"%s","event":{"kind":"alert","category":["intrusion_detection"],"type":["%s"],"severity":%d},"host":{"name":"%s"},"rule":{"name":"%s"},"aran":{"action":"%s","sdk_version":"6.3.0"}}
                """.formatted(event.timestamp(), event.action().toLowerCase(),
                event.severity().equalsIgnoreCase("Critical") ? 4 : 2,
                event.device(), event.type(), event.action()).trim();
    }

    private String formatGenericJSON(ThreatEvent event) {
        return """
                {"source":"aran-rasp","type":"%s","severity":"%s","device":"%s","action":"%s","timestamp":"%s"}
                """.formatted(event.type(), event.severity(), event.device(), event.action(), event.timestamp()).trim();
    }

    public record SiemConfig(String id, String name, String webhookUrl, String apiKey) {}

    public record ThreatEvent(String type, String severity, String device, String action, String timestamp) {
        public static ThreatEvent now(String type, String severity, String device, String action) {
            return new ThreatEvent(type, severity, device, action, Instant.now().toString());
        }
    }
}

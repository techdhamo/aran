package org.mazhai.central.demo;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Demo Data Seeder — ONLY active under the "demo" Spring profile.
 * Seeds demo users and continuously generates realistic threat telemetry
 * for enterprise demos and frontend ThreatCast API consumption.
 */
@Service
@Profile("demo")
@EnableScheduling
public class DemoDataSeederService {

    private static final Logger log = LoggerFactory.getLogger(DemoDataSeederService.class);

    // ── In-memory stores ──────────────────────────────────────────────────

    /** Demo users keyed by email */
    private final Map<String, DemoUser> users = new LinkedHashMap<>();

    /** Rolling window of threat events — newest first, capped at 10,000 */
    private final Deque<ThreatEvent> telemetryStream = new ConcurrentLinkedDeque<>();

    /** Aggregate counters for KPI cards */
    private volatile long totalThreatsBlocked = 0;
    private volatile long totalDevicesProtected = 12_847;
    private volatile int activeAlerts = 7;

    // ── Seed Demo Users ──────────────────────────────────────────────────

    @PostConstruct
    void seedUsers() {
        users.put("admin@mazhai.org", new DemoUser(
                UUID.randomUUID().toString(),
                "admin@mazhai.org",
                "Aran Platform Admin",
                "SUPER_ADMIN",
                "mazhai.org"
        ));
        users.put("ciso@acmebank.com", new DemoUser(
                UUID.randomUUID().toString(),
                "ciso@acmebank.com",
                "Sarah Chen — CISO",
                "TENANT",
                "acmebank.com"
        ));
        log.info("Demo seeder: created {} demo users → {}", users.size(), users.keySet());
    }

    // ── Continuous Telemetry Generator (Virtual Thread) ───────────────────

    @Scheduled(fixedRate = 2000)
    void generateTelemetry() {
        Thread.ofVirtual().name("demo-telemetry-gen").start(() -> {
            var rng = ThreadLocalRandom.current();
            int batchSize = rng.nextInt(1, 5); // 1-4 events per tick

            for (int i = 0; i < batchSize; i++) {
                var origin = ORIGINS[rng.nextInt(ORIGINS.length)];
                var threat = THREAT_TYPES[rng.nextInt(THREAT_TYPES.length)];
                var device = DEVICES[rng.nextInt(DEVICES.length)];
                var os = OS_VERSIONS[rng.nextInt(OS_VERSIONS.length)];
                var severity = SEVERITIES[rng.nextInt(SEVERITIES.length)];
                var action = pickAction(severity, rng);

                // Jitter coordinates ±2° for realism
                double lat = origin.lat + (rng.nextDouble() - 0.5) * 4.0;
                double lng = origin.lng + (rng.nextDouble() - 0.5) * 4.0;

                var event = new ThreatEvent(
                        UUID.randomUUID().toString(),
                        "ciso@acmebank.com",
                        Instant.now().toString(),
                        threat,
                        severity,
                        action,
                        device,
                        os,
                        origin.country,
                        origin.city,
                        generateRandomIp(rng),
                        lat,
                        lng,
                        generatePolymorphicSig(rng)
                );

                telemetryStream.addFirst(event);
                totalThreatsBlocked++;

                // Keep stream capped at 10,000
                while (telemetryStream.size() > 10_000) {
                    telemetryStream.removeLast();
                }
            }

            // Fluctuate active alerts
            activeAlerts = Math.max(1, activeAlerts + rng.nextInt(-1, 2));
        });
    }

    // ── Public Accessors (for REST controllers / WebSocket) ──────────────

    public Collection<DemoUser> getUsers() {
        return Collections.unmodifiableCollection(users.values());
    }

    public Optional<DemoUser> findUser(String email) {
        return Optional.ofNullable(users.get(email));
    }

    public List<ThreatEvent> getRecentEvents(int limit) {
        var list = new ArrayList<ThreatEvent>(Math.min(limit, telemetryStream.size()));
        var it = telemetryStream.iterator();
        for (int i = 0; i < limit && it.hasNext(); i++) {
            list.add(it.next());
        }
        return list;
    }

    public Map<String, Object> getKpiSnapshot() {
        return Map.of(
                "protectedDevices", totalDevicesProtected,
                "threatsBlocked", totalThreatsBlocked,
                "activeAlerts", activeAlerts,
                "totalEvents", telemetryStream.size()
        );
    }

    // ── Helper methods ───────────────────────────────────────────────────

    private static String pickAction(String severity, ThreadLocalRandom rng) {
        return switch (severity) {
            case "Critical" -> rng.nextBoolean() ? "Scorched Earth" : "Blocked";
            case "High" -> rng.nextInt(3) == 0 ? "Scorched Earth" : "Blocked";
            case "Medium" -> rng.nextBoolean() ? "Blocked" : "Reported";
            default -> "Reported";
        };
    }

    private static String generateRandomIp(ThreadLocalRandom rng) {
        return rng.nextInt(1, 224) + "." + rng.nextInt(0, 256) + "."
                + rng.nextInt(0, 256) + "." + rng.nextInt(1, 255);
    }

    private static String generatePolymorphicSig(ThreadLocalRandom rng) {
        return "ARAN-%04x-%04x-%04x".formatted(
                rng.nextInt(0xFFFF), rng.nextInt(0xFFFF), rng.nextInt(0xFFFF));
    }

    // ── Static data pools ────────────────────────────────────────────────

    private static final String[] THREAT_TYPES = {
            "Frida Gadget Hook",
            "Cydia Substrate Detected",
            "Magisk Hide Bypass",
            "Log4Shell Payload Dropped",
            "Root / Jailbreak Detection",
            "SSL Pinning Bypass (objection)",
            "Repackaged APK Detected",
            "Memory Spoofing (GameGuardian)",
            "Auto-Clicker Bot Injection",
            "Debugger Attached (lldb/gdb)",
            "Emulator Environment Detected",
            "Xposed Framework Active",
            "Zygisk Module Loaded",
            "Screen Capture Blocked",
            "OGNL Injection Attempt",
            "Command Injection via Header",
            "Path Traversal in API Call",
            "KernelSU Detected"
    };

    private static final String[] DEVICES = {
            "Pixel 8 Pro", "iPhone 15 Pro Max", "Galaxy S24 Ultra", "OnePlus 12",
            "Xiaomi 14 Pro", "iPad Air M2", "Pixel 7a", "iPhone 14",
            "Galaxy A54", "Huawei P60", "Nothing Phone 2", "Oppo Find X7"
    };

    private static final String[] OS_VERSIONS = {
            "Android 14", "Android 15", "Android 13", "iOS 17.4",
            "iOS 18.0", "iOS 17.2", "Android 14 (One UI 6)", "iPadOS 17.4"
    };

    private static final String[] SEVERITIES = {
            "Critical", "Critical", "High", "High", "High", "Medium", "Medium", "Low"
    };

    private static final GeoOrigin[] ORIGINS = {
            new GeoOrigin(40.7128, -74.0060, "US", "New York"),
            new GeoOrigin(51.5074, -0.1278, "UK", "London"),
            new GeoOrigin(19.0760, 72.8777, "IN", "Mumbai"),
            new GeoOrigin(39.9042, 116.4074, "CN", "Beijing"),
            new GeoOrigin(35.6762, 139.6503, "JP", "Tokyo"),
            new GeoOrigin(-23.5505, -46.6333, "BR", "São Paulo"),
            new GeoOrigin(6.5244, 3.3792, "NG", "Lagos"),
            new GeoOrigin(-33.8688, 151.2093, "AU", "Sydney"),
            new GeoOrigin(50.1109, 8.6821, "DE", "Frankfurt"),
            new GeoOrigin(43.6532, -79.3832, "CA", "Toronto"),
            new GeoOrigin(1.3521, 103.8198, "SG", "Singapore"),
            new GeoOrigin(37.5665, 126.9780, "KR", "Seoul"),
            new GeoOrigin(55.7558, 37.6173, "RU", "Moscow"),
            new GeoOrigin(25.2048, 55.2708, "AE", "Dubai"),
            new GeoOrigin(-34.6037, -58.3816, "AR", "Buenos Aires")
    };

    // ── Records ──────────────────────────────────────────────────────────

    public record DemoUser(String id, String email, String displayName, String role, String tenant) {}

    public record ThreatEvent(
            String id,
            String tenantEmail,
            String timestamp,
            String type,
            String severity,
            String action,
            String device,
            String os,
            String country,
            String city,
            String sourceIp,
            double latitude,
            double longitude,
            String polymorphicSignature
    ) {}

    private record GeoOrigin(double lat, double lng, String country, String city) {}
}

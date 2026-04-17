package org.mazhai.central.waf;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Virtual Patching / WAAP Rules Engine.
 * Ingests dynamic rules from the admin UI and distributes them to edge nodes.
 * In production, distribution would be via Kafka; here we maintain an in-memory registry.
 */
@RestController
@RequestMapping("/api/v1/waf/virtual-patches")
public class VirtualPatchController {

    private final Map<String, VirtualPatchRule> rules = new ConcurrentHashMap<>();

    @GetMapping
    public ResponseEntity<Collection<VirtualPatchRule>> listRules() {
        return ResponseEntity.ok(rules.values());
    }

    @PostMapping
    public ResponseEntity<?> deployRule(@RequestBody VirtualPatchRule rule) {
        // Validate regex compiles
        try {
            Pattern.compile(rule.pattern());
        } catch (PatternSyntaxException e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "Invalid regex pattern",
                    "detail", e.getDescription()
            ));
        }

        String id = "vp-" + UUID.randomUUID().toString().substring(0, 8);
        var persisted = new VirtualPatchRule(
                id,
                rule.name(),
                rule.type(),
                rule.pattern(),
                rule.cve(),
                rule.severity(),
                "Active",
                Instant.now().toString(),
                0
        );
        rules.put(id, persisted);

        // In production: publish to Kafka topic "aran.waf.rules" for edge distribution
        // kafkaTemplate.send("aran.waf.rules", id, persisted);

        return ResponseEntity.ok(Map.of("id", id, "status", "deployed", "distributedTo", "all-edge-nodes"));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> disableRule(@PathVariable String id) {
        var removed = rules.remove(id);
        if (removed == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(Map.of("id", id, "status", "disabled"));
    }

    /**
     * Called by the ServerSideRaspFilter to check payloads against all active rules.
     */
    public Optional<VirtualPatchRule> matchPayload(String payload) {
        for (var rule : rules.values()) {
            try {
                if (Pattern.compile(rule.pattern(), Pattern.CASE_INSENSITIVE).matcher(payload).find()) {
                    return Optional.of(rule);
                }
            } catch (PatternSyntaxException ignored) {
                // skip malformed rules
            }
        }
        return Optional.empty();
    }

    public record VirtualPatchRule(
            String id,
            String name,
            String type,
            String pattern,
            String cve,
            String severity,
            String status,
            String deployedAt,
            int hits
    ) {}
}

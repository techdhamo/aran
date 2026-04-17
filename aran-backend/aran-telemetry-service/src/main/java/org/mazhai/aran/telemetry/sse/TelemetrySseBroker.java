package org.mazhai.aran.telemetry.sse;

import org.mazhai.aran.telemetry.model.RbiThreatEvent;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * TelemetrySseBroker — fan-out broker for real-time RASP event streaming.
 *
 * Each SOC dashboard client connects via GET /api/v1/telemetry/stream and
 * receives an SseEmitter. When the ingest pipeline accepts a valid event,
 * it calls publish() to push a TelemetrySseEvent to all active emitters.
 *
 * Emitters are removed automatically on completion, timeout, or error.
 */
@Component
public class TelemetrySseBroker {

    private static final long SSE_TIMEOUT_MS = 5 * 60 * 1000L;   // 5 min
    private final CopyOnWriteArrayList<SseEmitter> emitters = new CopyOnWriteArrayList<>();

    public SseEmitter subscribe() {
        SseEmitter emitter = new SseEmitter(SSE_TIMEOUT_MS);
        emitters.add(emitter);
        Runnable remove = () -> emitters.remove(emitter);
        emitter.onCompletion(remove);
        emitter.onTimeout(remove);
        emitter.onError(e -> remove.run());
        return emitter;
    }

    public void publish(TelemetrySseEvent event) {
        List<SseEmitter> dead = new ArrayList<>();
        for (SseEmitter emitter : emitters) {
            try {
                emitter.send(
                    SseEmitter.event()
                        .name("threat")
                        .data(event)
                );
            } catch (IOException e) {
                dead.add(emitter);
            }
        }
        emitters.removeAll(dead);
    }

    public int activeSubscribers() {
        return emitters.size();
    }
}

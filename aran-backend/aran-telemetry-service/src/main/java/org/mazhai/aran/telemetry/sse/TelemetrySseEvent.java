package org.mazhai.aran.telemetry.sse;

import org.mazhai.aran.telemetry.model.RbiThreatEvent;

import java.util.List;

/**
 * Serialized form of a RASP event pushed over SSE.
 * Fields are a projection of RbiThreatEvent — no PII.
 */
public record TelemetrySseEvent(
        String eventId,
        long   timestamp,
        String severityLevel,
        String osType,
        String nativeThreatMask,
        String appId,
        String deviceFingerprint,
        List<String> categories,
        boolean isRooted,
        boolean fridaDetected,
        boolean zygiskDetected,
        boolean anonElfDetected,
        boolean overlayDetected,
        boolean screenRecording,
        boolean proxyDetected,
        int    malwareCount
) {
    public static TelemetrySseEvent from(RbiThreatEvent event, String correlationId) {
        var tv = event.threatVector();
        var dc = event.deviceContext();
        return new TelemetrySseEvent(
                correlationId,
                event.timestamp() != null ? event.timestamp() : 0L,
                event.severityLevel(),
                event.osType(),
                event.nativeThreatMask(),
                dc != null ? dc.appId() : null,
                dc != null ? dc.deviceFingerprint() : null,
                tv != null ? tv.categories() : List.of(),
                tv != null && tv.isRooted(),
                tv != null && tv.fridaDetected(),
                tv != null && tv.zygiskDetected(),
                tv != null && tv.anonElfDetected(),
                tv != null && tv.overlayDetected(),
                tv != null && tv.screenRecording(),
                tv != null && tv.proxyDetected(),
                tv != null ? tv.malwareCount() : 0
        );
    }
}

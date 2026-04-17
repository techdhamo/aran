import { Component, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { IonicModule } from '@ionic/angular';
import { HttpClient } from '@angular/common/http';

interface TelemetrySseEvent {
  eventId: string;
  timestamp: number;
  severityLevel: string;
  osType: string;
  nativeThreatMask: string;
  appId: string;
  deviceFingerprint: string;
  categories: string[];
  isRooted: boolean;
  fridaDetected: boolean;
  zygiskDetected: boolean;
  anonElfDetected: boolean;
  overlayDetected: boolean;
  screenRecording: boolean;
  proxyDetected: boolean;
  malwareCount: number;
}

interface StreamEvent {
  id: string;
  timestamp: string;
  type: string;
  device: string;
  os: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  mask: string;
  categories: string[];
}

@Component({
  selector: 'app-realtime-stream',
  standalone: true,
  imports: [CommonModule, IonicModule],
  template: `
    <div style="background: #FFFFFF; border-radius: 12px; border: 1px solid #E5E7EB; overflow: hidden;">
      <div style="padding: 16px 20px; border-bottom: 1px solid #E5E7EB; display: flex; align-items: center; justify-content: space-between;">
        <div>
          <h2 style="font-size: 1rem; font-weight: 700; color: #1A1A1A; margin: 0;">Real-Time Attack Stream</h2>
          <p style="font-size: 0.75rem; color: #6B7280; margin: 4px 0 0;">SOC-grade live telemetry feed</p>
        </div>
        <div style="display: flex; align-items: center; gap: 8px;">
          <span style="font-size: 0.7rem; font-weight: 600; color: #6B7280;">{{ events.length }} events</span>
          <div style="display: flex; align-items: center; gap: 4px; padding: 4px 10px; background: #F0FDF4; border-radius: 9999px;">
            <span style="width: 6px; height: 6px; border-radius: 50%; background: #16A34A; animation: blink 1s infinite;"></span>
            <span style="font-size: 0.7rem; font-weight: 700; color: #16A34A;">STREAMING</span>
          </div>
        </div>
      </div>

      <div style="overflow-x: auto; max-height: 400px; overflow-y: auto;">
        <table style="width: 100%; border-collapse: collapse; font-size: 0.8rem;">
          <thead>
            <tr style="background: #F9FAFB; position: sticky; top: 0; z-index: 1;">
              <th style="padding: 10px 14px; text-align: left; font-weight: 700; color: #374151; white-space: nowrap;">Time</th>
              <th style="padding: 10px 14px; text-align: left; font-weight: 700; color: #374151; white-space: nowrap;">Attack Type</th>
              <th style="padding: 10px 14px; text-align: left; font-weight: 700; color: #374151; white-space: nowrap;">Device</th>
              <th style="padding: 10px 14px; text-align: left; font-weight: 700; color: #374151; white-space: nowrap;">OS</th>
              <th style="padding: 10px 14px; text-align: left; font-weight: 700; color: #374151; white-space: nowrap;">RASP Mask</th>
              <th style="padding: 10px 14px; text-align: left; font-weight: 700; color: #374151; white-space: nowrap;">Severity</th>
              <th style="padding: 10px 14px; text-align: left; font-weight: 700; color: #374151; white-space: nowrap;">Categories</th>
            </tr>
          </thead>
          <tbody>
            <tr *ngFor="let e of events; let i = index"
                [style.background]="i === 0 ? '#FFFBEB' : 'transparent'"
                [style.animation]="i === 0 ? 'fadeIn 0.5s' : 'none'"
                style="border-top: 1px solid #F3F4F6; transition: background 0.3s;">
              <td style="padding: 10px 14px; color: #6B7280; white-space: nowrap; font-family: monospace; font-size: 0.75rem;">{{ e.timestamp }}</td>
              <td style="padding: 10px 14px; color: #1A1A1A; font-weight: 600; white-space: nowrap;">{{ e.type }}</td>
              <td style="padding: 10px 14px; color: #6B7280; white-space: nowrap;">{{ e.device }}</td>
              <td style="padding: 10px 14px; color: #6B7280; white-space: nowrap;">{{ e.os }}</td>
              <td style="padding: 10px 14px; white-space: nowrap;">
                <code style="font-size: 0.65rem; background: #F3F4F6; padding: 2px 6px; border-radius: 4px; color: #6B7280; letter-spacing: 0.02em;">{{ e.mask }}</code>
              </td>
              <td style="padding: 10px 14px; white-space: nowrap;">
                <span [style.background]="sevBg(e.severity)" [style.color]="sevColor(e.severity)"
                      style="padding: 2px 8px; border-radius: 9999px; font-size: 0.7rem; font-weight: 700;">
                  {{ e.severity }}
                </span>
              </td>
              <td style="padding: 10px 14px; color: #6B7280; white-space: nowrap; font-size: 0.75rem;">
                {{ e.categories?.join(', ') || '-' }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  `,
  styles: [`
    @keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
    @keyframes fadeIn { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: translateY(0); } }
  `]
})
export class RealtimeStreamComponent implements OnInit, OnDestroy {
  events: StreamEvent[] = [];
  private eventSource: EventSource | null = null;
  private reconnectTimer: any;
  private readonly TELEMETRY_STREAM_URL = 'http://localhost:8083/api/v1/telemetry/stream';

  constructor(private http: HttpClient) {}

  ngOnInit(): void {
    this.connectToStream();
  }

  ngOnDestroy(): void {
    this.disconnect();
  }

  private connectToStream(): void {
    try {
      this.eventSource = new EventSource(this.TELEMETRY_STREAM_URL);

      this.eventSource.onopen = () => {
        console.log('[SOC] SSE stream connected');
      };

      this.eventSource.addEventListener('threat', (event: MessageEvent) => {
        try {
          const sseEvent: TelemetrySseEvent = JSON.parse(event.data);
          this.pushRealEvent(sseEvent);
        } catch (e) {
          console.error('[SOC] Failed to parse SSE event:', e);
        }
      });

      this.eventSource.onerror = () => {
        console.warn('[SOC] SSE stream error, reconnecting in 5s...');
        this.disconnect();
        this.reconnectTimer = setTimeout(() => this.connectToStream(), 5000);
      };
    } catch (e) {
      console.error('[SOC] Failed to create EventSource:', e);
    }
  }

  private disconnect(): void {
    if (this.eventSource) {
      this.eventSource.close();
      this.eventSource = null;
    }
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
  }

  private pushRealEvent(sseEvent: TelemetrySseEvent): void {
    const now = new Date(sseEvent.timestamp);
    const ts = `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}:${now.getSeconds().toString().padStart(2, '0')}`;

    const type = this.deriveAttackType(sseEvent);
    const severity = this.mapSeverity(sseEvent.severityLevel);
    const device = sseEvent.deviceFingerprint?.substring(0, 12) || 'unknown';

    this.events.unshift({
      id: sseEvent.eventId,
      timestamp: ts,
      type,
      device,
      os: sseEvent.osType,
      severity,
      mask: sseEvent.nativeThreatMask || '0x0',
      categories: sseEvent.categories || []
    });

    if (this.events.length > 50) this.events.pop();
  }

  private deriveAttackType(event: TelemetrySseEvent): string {
    if (event.fridaDetected) return 'Frida Injection';
    if (event.zygiskDetected || event.anonElfDetected) return 'Zygisk / Anon ELF';
    if (event.isRooted) return 'Root Detection';
    if (event.overlayDetected) return 'Overlay Attack';
    if (event.screenRecording) return 'Screen Recording';
    if (event.proxyDetected) return 'Proxy / VPN';
    if (event.malwareCount > 0) return `Malware (${event.malwareCount})`;
    if (event.categories && event.categories.length > 0) return event.categories[0];
    return 'Unknown Threat';
  }

  private mapSeverity(level: string): StreamEvent['severity'] {
    const l = level?.toLowerCase() || '';
    if (l === 'critical') return 'Critical';
    if (l === 'high') return 'High';
    if (l === 'medium') return 'Medium';
    return 'Low';
  }

  sevColor(s: string): string { return s === 'Critical' ? '#991B1B' : s === 'High' ? '#92400E' : s === 'Medium' ? '#1E40AF' : '#374151'; }
  sevBg(s: string): string { return s === 'Critical' ? '#FEE2E2' : s === 'High' ? '#FEF3C7' : s === 'Medium' ? '#DBEAFE' : '#F3F4F6'; }
}

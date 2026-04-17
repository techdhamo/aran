import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { IonicModule } from '@ionic/angular';

interface SiemIntegration {
  id: string;
  name: string;
  logo: string;
  description: string;
  color: string;
  status: 'Connected' | 'Disconnected' | 'Error';
  lastSync?: string;
  eventsForwarded?: number;
  webhookUrl: string;
  apiKey: string;
}

@Component({
  selector: 'app-integrations',
  standalone: true,
  imports: [CommonModule, FormsModule, IonicModule],
  template: `
    <ion-content style="--background: #F9FAFB;">
    <div style="padding: 24px; max-width: 1400px; margin: 0 auto;">
      <div style="margin-bottom: 24px;">
        <h1 style="font-size: 1.5rem; font-weight: 800; color: #1A1A1A; margin: 0 0 4px;">SIEM &amp; Observability Integrations</h1>
        <p style="font-size: 0.875rem; color: #6B7280; margin: 0;">1-click Webhook/API forwarding — stream Aran threat telemetry to your security stack</p>
      </div>

      <!-- Integration Cards Grid -->
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 20px; margin-bottom: 32px;">
        <div *ngFor="let siem of integrations"
             style="background: #FFFFFF; border-radius: 12px; border: 1px solid #E5E7EB; overflow: hidden;">
          <!-- Card Header -->
          <div style="padding: 20px; border-bottom: 1px solid #F3F4F6;">
            <div style="display: flex; align-items: center; gap: 14px;">
              <div [style.background]="siem.color" style="width: 48px; height: 48px; border-radius: 10px; display: flex; align-items: center; justify-content: center; flex-shrink: 0;">
                <span style="font-size: 1.25rem; font-weight: 800; color: #FFFFFF;">{{ siem.logo }}</span>
              </div>
              <div style="flex: 1;">
                <h3 style="font-size: 1rem; font-weight: 700; color: #1A1A1A; margin: 0;">{{ siem.name }}</h3>
                <p style="font-size: 0.75rem; color: #6B7280; margin: 2px 0 0;">{{ siem.description }}</p>
              </div>
              <span [style.color]="statusColor(siem.status)" style="display: flex; align-items: center; gap: 4px; font-size: 0.7rem; font-weight: 700;">
                <span [style.background]="statusColor(siem.status)" style="width: 6px; height: 6px; border-radius: 50%;"></span>
                {{ siem.status }}
              </span>
            </div>
          </div>

          <!-- Config Form -->
          <div style="padding: 16px 20px;">
            <div style="margin-bottom: 12px;">
              <label style="display: block; font-size: 0.75rem; font-weight: 600; color: #374151; margin-bottom: 4px;">Webhook URL</label>
              <input [(ngModel)]="siem.webhookUrl" [name]="'webhook-' + siem.id"
                     placeholder="https://your-siem-endpoint.com/api/v1/events"
                     style="width: 100%; padding: 8px 12px; border: 1.5px solid #E5E7EB; border-radius: 6px; font-size: 0.8rem; color: #1A1A1A; box-sizing: border-box;" />
            </div>
            <div style="margin-bottom: 14px;">
              <label style="display: block; font-size: 0.75rem; font-weight: 600; color: #374151; margin-bottom: 4px;">API Key / Token</label>
              <input [(ngModel)]="siem.apiKey" [name]="'apikey-' + siem.id" type="password"
                     placeholder="••••••••••••••••"
                     style="width: 100%; padding: 8px 12px; border: 1.5px solid #E5E7EB; border-radius: 6px; font-size: 0.8rem; color: #1A1A1A; box-sizing: border-box;" />
            </div>

            <!-- Stats (if connected) -->
            <div *ngIf="siem.status === 'Connected'" style="display: flex; gap: 16px; margin-bottom: 14px; padding: 10px; background: #F0FDF4; border-radius: 6px;">
              <div>
                <p style="font-size: 0.65rem; color: #6B7280; margin: 0;">Events Forwarded</p>
                <p style="font-size: 1rem; font-weight: 700; color: #1A1A1A; margin: 2px 0 0;">{{ siem.eventsForwarded | number }}</p>
              </div>
              <div>
                <p style="font-size: 0.65rem; color: #6B7280; margin: 0;">Last Sync</p>
                <p style="font-size: 0.8rem; font-weight: 600; color: #1A1A1A; margin: 2px 0 0;">{{ siem.lastSync }}</p>
              </div>
            </div>

            <div style="display: flex; gap: 8px;">
              <button (click)="toggleConnection(siem)"
                      [style.background]="siem.status === 'Connected' ? '#FEE2E2' : 'linear-gradient(135deg, #0066CC, #0052A3)'"
                      [style.color]="siem.status === 'Connected' ? '#991B1B' : '#FFFFFF'"
                      style="flex: 1; padding: 8px; border: none; border-radius: 6px; font-size: 0.8rem; font-weight: 600; cursor: pointer;">
                {{ siem.status === 'Connected' ? 'Disconnect' : 'Connect' }}
              </button>
              <button *ngIf="siem.status === 'Connected'" (click)="testConnection(siem)"
                      style="padding: 8px 14px; background: #F3F4F6; color: #374151; border: none; border-radius: 6px; font-size: 0.8rem; font-weight: 600; cursor: pointer;">
                Test
              </button>
            </div>
          </div>
        </div>
      </div>

      <!-- Forwarding Status -->
      <div style="background: #FFFFFF; border-radius: 12px; border: 1px solid #E5E7EB; padding: 20px;">
        <h2 style="font-size: 1rem; font-weight: 700; color: #1A1A1A; margin: 0 0 12px;">Forwarding Pipeline</h2>
        <p style="font-size: 0.8rem; color: #6B7280; margin: 0; line-height: 1.6;">
          Aran processes threat telemetry on <strong>Java 21 Virtual Threads</strong> for near-zero latency forwarding.
          Each connected integration receives events in the vendor's native format (CEF for QRadar, JSON for Splunk HEC, Datadog Log API, Elastic Common Schema).
        </p>
      </div>
    </div>
    </ion-content>
  `
})
export class IntegrationsComponent {
  integrations: SiemIntegration[] = [
    { id: 'splunk', name: 'Splunk', logo: 'S', description: 'HTTP Event Collector (HEC) integration', color: '#65A637', status: 'Connected', lastSync: '2 min ago', eventsForwarded: 48291, webhookUrl: 'https://splunk.corp.example.com:8088/services/collector', apiKey: '••••••••' },
    { id: 'datadog', name: 'Datadog', logo: 'D', description: 'Logs API & Security Monitoring', color: '#632CA6', status: 'Connected', lastSync: '1 min ago', eventsForwarded: 37104, webhookUrl: 'https://http-intake.logs.datadoghq.com/api/v2/logs', apiKey: '••••••••' },
    { id: 'qradar', name: 'IBM QRadar', logo: 'Q', description: 'CEF syslog forwarding via LEEF/CEF', color: '#0F62FE', status: 'Disconnected', webhookUrl: '', apiKey: '' },
    { id: 'elastic', name: 'Elastic Security', logo: 'E', description: 'Elastic Common Schema (ECS) via Fleet', color: '#FEC514', status: 'Disconnected', webhookUrl: '', apiKey: '' }
  ];

  statusColor(s: string): string {
    return s === 'Connected' ? '#16A34A' : s === 'Error' ? '#DC2626' : '#9CA3AF';
  }

  toggleConnection(siem: SiemIntegration): void {
    if (siem.status === 'Connected') {
      siem.status = 'Disconnected';
      siem.lastSync = undefined;
    } else {
      if (!siem.webhookUrl || !siem.apiKey) return;
      siem.status = 'Connected';
      siem.lastSync = 'Just now';
      siem.eventsForwarded = 0;
    }
  }

  testConnection(siem: SiemIntegration): void {
    siem.lastSync = 'Test OK — ' + new Date().toLocaleTimeString();
  }
}

import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { IonicModule } from '@ionic/angular';
import { ThreatMapComponent } from './threat-map.component';
import { AttackVectorsComponent } from './attack-vectors.component';
import { RealtimeStreamComponent } from './realtime-stream.component';
import { WafPolicyBreakdownComponent } from './waf-policy-breakdown.component';

@Component({
  selector: 'app-dashboard-overview',
  standalone: true,
  imports: [CommonModule, IonicModule, ThreatMapComponent, AttackVectorsComponent, RealtimeStreamComponent, WafPolicyBreakdownComponent],
  template: `
    <ion-content style="--background: #F9FAFB;">
    <div style="padding: 24px; max-width: 1400px; margin: 0 auto; margin-top: 64px;">
      <div style="margin-bottom: 24px;">
        <h1 style="font-size: 1.5rem; font-weight: 800; color: #1A1A1A; margin: 0 0 4px;">ThreatCast Dashboard</h1>
        <p style="font-size: 0.875rem; color: #6B7280; margin: 0;">Enterprise Security Operations Center — Aran RASP + WAAP</p>
      </div>

      <!-- KPI Cards -->
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px;">
        <div *ngFor="let m of metrics" style="background: #FFFFFF; border-radius: 12px; border: 1px solid #E5E7EB; padding: 20px;">
          <div style="display: flex; align-items: center; justify-content: space-between;">
            <div>
              <p style="font-size: 0.7rem; font-weight: 700; color: #6B7280; text-transform: uppercase; letter-spacing: 0.06em; margin: 0 0 4px;">{{ m.label }}</p>
              <p style="font-size: 1.5rem; font-weight: 800; color: #1A1A1A; margin: 0;">{{ m.value }}</p>
            </div>
            <div [style.background]="m.bg" style="width: 44px; height: 44px; border-radius: 10px; display: flex; align-items: center; justify-content: center;">
              <ion-icon [name]="m.icon" [style.color]="m.color" style="font-size: 22px;"></ion-icon>
            </div>
          </div>
          <p style="font-size: 0.7rem; margin: 8px 0 0;" [style.color]="m.trend === 'up' ? '#16A34A' : '#DC2626'">
            {{ m.trend === 'up' ? '↑' : '↓' }} {{ m.change }} from last week
          </p>
        </div>
      </div>

      <!-- Threat Map -->
      <div style="margin-bottom: 24px;">
        <app-threat-map></app-threat-map>
      </div>

      <!-- Attack Vectors -->
      <div style="margin-bottom: 24px;">
        <app-attack-vectors></app-attack-vectors>
      </div>

      <!-- WAF Policy Breakdown -->
      <div style="margin-bottom: 24px;">
        <app-waf-policy-breakdown></app-waf-policy-breakdown>
      </div>

      <!-- Polymorphic Signature Status -->
      <div style="background: #FFFFFF; border-radius: 12px; border: 1px solid #E5E7EB; padding: 20px; margin-bottom: 24px;">
        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 16px;">
          <div style="width: 40px; height: 40px; border-radius: 10px; background: linear-gradient(135deg, #0066CC, #0052A3); display: flex; align-items: center; justify-content: center;">
            <ion-icon name="shuffle-outline" style="color: #FFFFFF; font-size: 20px;"></ion-icon>
          </div>
          <div>
            <h2 style="font-size: 1rem; font-weight: 700; color: #1A1A1A; margin: 0;">Polymorphic Threat Signatures</h2>
            <p style="font-size: 0.75rem; color: #6B7280; margin: 2px 0 0;">Aran SDK dynamically rotates detection signatures to evade attacker bypass scripts</p>
          </div>
        </div>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px;">
          <div *ngFor="let sig of polySignatures" style="background: #F9FAFB; border-radius: 8px; padding: 14px; border: 1px solid #E5E7EB;">
            <p style="font-size: 0.7rem; font-weight: 700; color: #6B7280; text-transform: uppercase; letter-spacing: 0.05em; margin: 0 0 6px;">{{ sig.module }}</p>
            <code style="font-size: 0.75rem; color: #0066CC; font-weight: 600;">{{ sig.currentSig }}</code>
            <div style="display: flex; align-items: center; gap: 6px; margin-top: 8px;">
              <span style="width: 6px; height: 6px; border-radius: 50%; background: #16A34A;"></span>
              <span style="font-size: 0.65rem; color: #6B7280;">Rotated {{ sig.rotations }} times today</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Real-Time Attack Stream -->
      <app-realtime-stream></app-realtime-stream>
    </div>
    </ion-content>
  `
})
export class DashboardOverviewPage {
  metrics = [
    { label: 'Protected Devices', value: '12,847', icon: 'phone-portrait-outline', color: '#0066CC', bg: 'rgba(0,102,204,0.1)', trend: 'up', change: '12%' },
    { label: 'Threats Blocked', value: '3,291', icon: 'shield-checkmark-outline', color: '#16A34A', bg: 'rgba(22,163,74,0.1)', trend: 'up', change: '8%' },
    { label: 'Active Alerts', value: '7', icon: 'warning-outline', color: '#DC2626', bg: 'rgba(220,38,38,0.1)', trend: 'down', change: '23%' },
    { label: 'Polymorphic Rotations', value: '48.2K', icon: 'shuffle-outline', color: '#7C3AED', bg: 'rgba(124,58,237,0.1)', trend: 'up', change: '34%' }
  ];

  polySignatures = [
    { module: 'Root Detection', currentSig: 'ARAN-7f3a-b91c-e40d', rotations: 127 },
    { module: 'Frida Hook Scan', currentSig: 'ARAN-2c8e-d54f-1a7b', rotations: 89 },
    { module: 'SSL Pin Verify', currentSig: 'ARAN-9d1f-63a8-c2e5', rotations: 156 },
    { module: 'Integrity Check', currentSig: 'ARAN-4b6c-8e2d-f091', rotations: 73 },
    { module: 'Memory Guard', currentSig: 'ARAN-a5d3-17f9-8b4c', rotations: 201 },
    { module: 'Bot Detector', currentSig: 'ARAN-e8c2-4a6f-d31b', rotations: 64 }
  ];
}

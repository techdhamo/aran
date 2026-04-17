import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { IonicModule } from '@ionic/angular';

interface AttackVector {
  name: string;
  icon: string;
  count: number;
  trend: number;
  severity: 'Critical' | 'High' | 'Medium';
  description: string;
}

@Component({
  selector: 'app-attack-vectors',
  standalone: true,
  imports: [CommonModule, IonicModule],
  template: `
    <div style="background: #FFFFFF; border-radius: 12px; border: 1px solid #E5E7EB; overflow: hidden;">
      <div style="padding: 16px 20px; border-bottom: 1px solid #E5E7EB;">
        <h2 style="font-size: 1rem; font-weight: 700; color: #1A1A1A; margin: 0;">Attack Vector Analysis</h2>
        <p style="font-size: 0.75rem; color: #6B7280; margin: 4px 0 0;">Top threat categories — rolling 7-day window</p>
      </div>
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 0;">
        <div *ngFor="let v of vectors; let last = last"
             [style.borderRight]="last ? 'none' : '1px solid #F3F4F6'"
             style="padding: 20px; border-bottom: 1px solid #F3F4F6;">
          <div style="display: flex; align-items: flex-start; gap: 14px;">
            <div [style.background]="severityBg(v.severity)" style="width: 44px; height: 44px; border-radius: 10px; display: flex; align-items: center; justify-content: center; flex-shrink: 0;">
              <ion-icon [name]="v.icon" [style.color]="severityColor(v.severity)" style="font-size: 22px;"></ion-icon>
            </div>
            <div style="flex: 1; min-width: 0;">
              <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 4px;">
                <h3 style="font-size: 0.875rem; font-weight: 700; color: #1A1A1A; margin: 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">{{ v.name }}</h3>
                <span [style.background]="severityBg(v.severity)" [style.color]="severityColor(v.severity)"
                      style="padding: 2px 8px; border-radius: 9999px; font-size: 0.65rem; font-weight: 700; flex-shrink: 0; margin-left: 8px;">
                  {{ v.severity }}
                </span>
              </div>
              <p style="font-size: 0.75rem; color: #6B7280; margin: 0 0 8px; line-height: 1.4;">{{ v.description }}</p>
              <div style="display: flex; align-items: center; gap: 12px;">
                <span style="font-size: 1.25rem; font-weight: 800; color: #1A1A1A;">{{ v.count | number }}</span>
                <span [style.color]="v.trend > 0 ? '#DC2626' : '#16A34A'" style="font-size: 0.75rem; font-weight: 600;">
                  {{ v.trend > 0 ? '↑' : '↓' }} {{ v.trend > 0 ? '+' : '' }}{{ v.trend }}%
                </span>
                <!-- Mini bar -->
                <div style="flex: 1; height: 4px; background: #F3F4F6; border-radius: 2px; overflow: hidden;">
                  <div [style.width.%]="Math.min(100, (v.count / maxCount) * 100)" [style.background]="severityColor(v.severity)" style="height: 100%; border-radius: 2px; transition: width 0.5s;"></div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  `
})
export class AttackVectorsComponent {
  Math = Math;

  vectors: AttackVector[] = [
    { name: 'Hooking Frameworks (Frida/Substrate)', icon: 'git-branch-outline', count: 1247, trend: 18, severity: 'Critical', description: 'Dynamic instrumentation detected — Frida, Substrate, and Xposed hooking attempts.' },
    { name: 'Repackaging Attempts', icon: 'copy-outline', count: 892, trend: -5, severity: 'Critical', description: 'Modified APK/IPA binaries with altered signatures or injected payloads.' },
    { name: 'Memory Spoofing', icon: 'hardware-chip-outline', count: 634, trend: 31, severity: 'High', description: 'Runtime memory manipulation — GameGuardian, Cheat Engine, and custom mmap hooks.' },
    { name: 'Macro/Auto-Clicker Bots', icon: 'finger-print-outline', count: 421, trend: 12, severity: 'High', description: 'Automated input injection via accessibility services and virtual input devices.' },
    { name: 'SSL Pinning Bypass', icon: 'lock-open-outline', count: 318, trend: -8, severity: 'High', description: 'Certificate unpinning via objection, SSLKillSwitch, and custom proxy certs.' },
    { name: 'Emulator / Virtual Device', icon: 'desktop-outline', count: 203, trend: -15, severity: 'Medium', description: 'Execution on emulators, cloud phones, and virtualised ARM environments.' }
  ];

  get maxCount(): number {
    return Math.max(...this.vectors.map(v => v.count));
  }

  severityColor(s: string): string {
    return s === 'Critical' ? '#DC2626' : s === 'High' ? '#F59E0B' : '#0066CC';
  }

  severityBg(s: string): string {
    return s === 'Critical' ? '#FEE2E2' : s === 'High' ? '#FEF3C7' : '#DBEAFE';
  }
}

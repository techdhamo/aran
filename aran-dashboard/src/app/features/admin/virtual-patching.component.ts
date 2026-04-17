import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { IonicModule } from '@ionic/angular';

interface VirtualPatch {
  id: string;
  name: string;
  type: 'CVE' | 'Regex' | 'OGNL' | 'SQLi' | 'Custom';
  pattern: string;
  cve?: string;
  severity: 'Critical' | 'High' | 'Medium';
  status: 'Active' | 'Draft' | 'Disabled';
  deployedAt: string;
  hits: number;
}

@Component({
  selector: 'app-virtual-patching',
  standalone: true,
  imports: [CommonModule, FormsModule, IonicModule],
  template: `
    <ion-content style="--background: #F9FAFB;">
    <div style="padding: 24px; max-width: 1400px; margin: 0 auto;">
      <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 24px; flex-wrap: wrap; gap: 12px;">
        <div>
          <h1 style="font-size: 1.5rem; font-weight: 800; color: #1A1A1A; margin: 0 0 4px;">Virtual Patching &amp; WAAP Rules</h1>
          <p style="font-size: 0.875rem; color: #6B7280; margin: 0;">Deploy runtime protection rules instantly — no app update required</p>
        </div>
        <button (click)="showForm = !showForm"
                style="padding: 10px 20px; background: linear-gradient(135deg, #0066CC, #0052A3); color: #FFFFFF; border: none; border-radius: 8px; font-size: 0.875rem; font-weight: 600; cursor: pointer; display: flex; align-items: center; gap: 6px;">
          <ion-icon name="add-outline" style="font-size: 18px;"></ion-icon>
          New Virtual Patch
        </button>
      </div>

      <!-- Create Patch Form -->
      <div *ngIf="showForm" style="background: #FFFFFF; border-radius: 12px; border: 1px solid #E5E7EB; padding: 24px; margin-bottom: 24px;">
        <h2 style="font-size: 1rem; font-weight: 700; color: #1A1A1A; margin: 0 0 20px;">Deploy New Virtual Patch</h2>
        <form (ngSubmit)="deployPatch()">
          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px;">
            <div>
              <label style="display: block; font-size: 0.8rem; font-weight: 600; color: #1A1A1A; margin-bottom: 6px;">Rule Name</label>
              <input [(ngModel)]="newPatch.name" name="name" required placeholder="e.g. Log4Shell Mitigation"
                     style="width: 100%; padding: 10px 14px; border: 2px solid #E5E7EB; border-radius: 8px; font-size: 0.875rem; color: #1A1A1A; box-sizing: border-box;" />
            </div>
            <div>
              <label style="display: block; font-size: 0.8rem; font-weight: 600; color: #1A1A1A; margin-bottom: 6px;">Type</label>
              <select [(ngModel)]="newPatch.type" name="type"
                      style="width: 100%; padding: 10px 14px; border: 2px solid #E5E7EB; border-radius: 8px; font-size: 0.875rem; color: #1A1A1A; background: #FFF; box-sizing: border-box;">
                <option value="CVE">CVE Signature</option>
                <option value="Regex">Regex Pattern</option>
                <option value="SQLi">SQL Injection</option>
                <option value="OGNL">OGNL Injection</option>
                <option value="Custom">Custom Rule</option>
              </select>
            </div>
            <div>
              <label style="display: block; font-size: 0.8rem; font-weight: 600; color: #1A1A1A; margin-bottom: 6px;">CVE ID (optional)</label>
              <input [(ngModel)]="newPatch.cve" name="cve" placeholder="e.g. CVE-2021-44228"
                     style="width: 100%; padding: 10px 14px; border: 2px solid #E5E7EB; border-radius: 8px; font-size: 0.875rem; color: #1A1A1A; box-sizing: border-box;" />
            </div>
            <div>
              <label style="display: block; font-size: 0.8rem; font-weight: 600; color: #1A1A1A; margin-bottom: 6px;">Severity</label>
              <select [(ngModel)]="newPatch.severity" name="severity"
                      style="width: 100%; padding: 10px 14px; border: 2px solid #E5E7EB; border-radius: 8px; font-size: 0.875rem; color: #1A1A1A; background: #FFF; box-sizing: border-box;">
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
              </select>
            </div>
          </div>
          <div style="margin-top: 16px;">
            <label style="display: block; font-size: 0.8rem; font-weight: 600; color: #1A1A1A; margin-bottom: 6px;">Detection Pattern (Regex)</label>
            <textarea [(ngModel)]="newPatch.pattern" name="pattern" rows="3" required
                      placeholder="(?i)\\$\\{jndi:(ldap|rmi|dns)://.*\\}"
                      style="width: 100%; padding: 10px 14px; border: 2px solid #E5E7EB; border-radius: 8px; font-size: 0.8rem; font-family: monospace; color: #1A1A1A; resize: vertical; box-sizing: border-box;"></textarea>
          </div>
          <div style="display: flex; gap: 12px; margin-top: 20px;">
            <button type="submit" [disabled]="!newPatch.name || !newPatch.pattern"
                    style="padding: 10px 24px; background: linear-gradient(135deg, #0066CC, #0052A3); color: #FFF; border: none; border-radius: 8px; font-weight: 600; font-size: 0.875rem; cursor: pointer;"
                    [style.opacity]="!newPatch.name || !newPatch.pattern ? '0.5' : '1'">
              <ion-icon name="rocket-outline" style="margin-right: 6px;"></ion-icon>
              Deploy to Edge
            </button>
            <button type="button" (click)="showForm = false"
                    style="padding: 10px 24px; background: #F3F4F6; color: #374151; border: none; border-radius: 8px; font-weight: 600; font-size: 0.875rem; cursor: pointer;">
              Cancel
            </button>
          </div>
        </form>
      </div>

      <!-- Active Patches Table -->
      <div style="background: #FFFFFF; border-radius: 12px; border: 1px solid #E5E7EB; overflow: hidden;">
        <div style="padding: 16px 20px; border-bottom: 1px solid #E5E7EB; display: flex; align-items: center; justify-content: space-between;">
          <h2 style="font-size: 1rem; font-weight: 700; color: #1A1A1A; margin: 0;">Deployed Rules ({{ patches.length }})</h2>
          <span style="font-size: 0.75rem; color: #6B7280;">Distributed via Kafka to all edge nodes</span>
        </div>
        <div style="overflow-x: auto;">
          <table style="width: 100%; border-collapse: collapse; font-size: 0.8rem;">
            <thead>
              <tr style="background: #F9FAFB;">
                <th style="padding: 10px 14px; text-align: left; font-weight: 700; color: #374151;">Rule Name</th>
                <th style="padding: 10px 14px; text-align: left; font-weight: 700; color: #374151;">Type</th>
                <th style="padding: 10px 14px; text-align: left; font-weight: 700; color: #374151;">CVE</th>
                <th style="padding: 10px 14px; text-align: left; font-weight: 700; color: #374151;">Pattern</th>
                <th style="padding: 10px 14px; text-align: left; font-weight: 700; color: #374151;">Severity</th>
                <th style="padding: 10px 14px; text-align: left; font-weight: 700; color: #374151;">Status</th>
                <th style="padding: 10px 14px; text-align: right; font-weight: 700; color: #374151;">Hits</th>
              </tr>
            </thead>
            <tbody>
              <tr *ngFor="let p of patches" style="border-top: 1px solid #F3F4F6;">
                <td style="padding: 10px 14px; font-weight: 600; color: #1A1A1A;">{{ p.name }}</td>
                <td style="padding: 10px 14px;"><span style="padding: 2px 8px; background: #EFF6FF; color: #1E40AF; border-radius: 4px; font-size: 0.7rem; font-weight: 700;">{{ p.type }}</span></td>
                <td style="padding: 10px 14px; color: #6B7280; font-family: monospace; font-size: 0.75rem;">{{ p.cve || '—' }}</td>
                <td style="padding: 10px 14px;"><code style="font-size: 0.7rem; background: #F3F4F6; padding: 2px 6px; border-radius: 4px; color: #6B7280; max-width: 200px; overflow: hidden; text-overflow: ellipsis; display: inline-block; white-space: nowrap;">{{ p.pattern }}</code></td>
                <td style="padding: 10px 14px;">
                  <span [style.background]="p.severity === 'Critical' ? '#FEE2E2' : p.severity === 'High' ? '#FEF3C7' : '#DBEAFE'"
                        [style.color]="p.severity === 'Critical' ? '#991B1B' : p.severity === 'High' ? '#92400E' : '#1E40AF'"
                        style="padding: 2px 8px; border-radius: 9999px; font-size: 0.7rem; font-weight: 700;">{{ p.severity }}</span>
                </td>
                <td style="padding: 10px 14px;">
                  <span [style.color]="p.status === 'Active' ? '#16A34A' : p.status === 'Draft' ? '#F59E0B' : '#9CA3AF'" style="font-weight: 600; font-size: 0.75rem; display: flex; align-items: center; gap: 4px;">
                    <span [style.background]="p.status === 'Active' ? '#16A34A' : p.status === 'Draft' ? '#F59E0B' : '#9CA3AF'" style="width: 6px; height: 6px; border-radius: 50%;"></span>
                    {{ p.status }}
                  </span>
                </td>
                <td style="padding: 10px 14px; text-align: right; font-weight: 700; color: #1A1A1A;">{{ p.hits | number }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
    </ion-content>
  `
})
export class VirtualPatchingComponent {
  showForm = false;
  newPatch = { name: '', type: 'CVE', cve: '', pattern: '', severity: 'Critical' };

  patches: VirtualPatch[] = [
    { id: 'vp-1', name: 'Log4Shell (JNDI Lookup)', type: 'CVE', pattern: '(?i)\\$\\{jndi:(ldap|rmi|dns)://.*\\}', cve: 'CVE-2021-44228', severity: 'Critical', status: 'Active', deployedAt: '2026-02-20', hits: 14203 },
    { id: 'vp-2', name: 'Spring4Shell RCE', type: 'CVE', pattern: 'class\\.module\\.classLoader', cve: 'CVE-2022-22965', severity: 'Critical', status: 'Active', deployedAt: '2026-02-18', hits: 3891 },
    { id: 'vp-3', name: 'SQL Injection (Union-Based)', type: 'SQLi', pattern: '(?i)(union\\s+(all\\s+)?select|select.*from.*information_schema)', severity: 'High', status: 'Active', deployedAt: '2026-02-15', hits: 8472 },
    { id: 'vp-4', name: 'OGNL Injection (Struts)', type: 'OGNL', pattern: '(?i)(%\\{|\\$\\{|#\\{).*(@|java\\.lang)', cve: 'CVE-2017-5638', severity: 'Critical', status: 'Active', deployedAt: '2026-02-10', hits: 1203 },
    { id: 'vp-5', name: 'Path Traversal Block', type: 'Regex', pattern: '(\\.\\./|\\.\\.\\\\|%2e%2e)', severity: 'High', status: 'Active', deployedAt: '2026-02-08', hits: 5621 },
    { id: 'vp-6', name: 'XSS Script Injection', type: 'Regex', pattern: '(?i)<script[^>]*>|javascript:|on\\w+\\s*=', severity: 'Medium', status: 'Active', deployedAt: '2026-02-05', hits: 12904 }
  ];

  deployPatch(): void {
    if (!this.newPatch.name || !this.newPatch.pattern) return;
    this.patches.unshift({
      id: `vp-${Date.now()}`,
      name: this.newPatch.name,
      type: this.newPatch.type as any,
      pattern: this.newPatch.pattern,
      cve: this.newPatch.cve || undefined,
      severity: this.newPatch.severity as any,
      status: 'Active',
      deployedAt: new Date().toISOString().split('T')[0],
      hits: 0
    });
    this.newPatch = { name: '', type: 'CVE', cve: '', pattern: '', severity: 'Critical' };
    this.showForm = false;
  }
}

import { Component, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { IonicModule } from '@ionic/angular';

interface GeoThreat {
  id: string;
  lat: number;
  lng: number;
  city: string;
  country: string;
  type: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  timestamp: string;
}

@Component({
  selector: 'app-threat-map',
  standalone: true,
  imports: [CommonModule, IonicModule],
  template: `
    <div style="background: #FFFFFF; border-radius: 12px; border: 1px solid #E5E7EB; overflow: hidden;">
      <div style="padding: 16px 20px; border-bottom: 1px solid #E5E7EB; display: flex; align-items: center; justify-content: space-between;">
        <div>
          <h2 style="font-size: 1rem; font-weight: 700; color: #1A1A1A; margin: 0;">ThreatCast Global Map</h2>
          <p style="font-size: 0.75rem; color: #6B7280; margin: 4px 0 0;">Live attack origins — last 60 minutes</p>
        </div>
        <div style="display: flex; align-items: center; gap: 6px;">
          <span style="width: 8px; height: 8px; border-radius: 50%; background: #16A34A; animation: pulse 1.5s infinite;"></span>
          <span style="font-size: 0.75rem; font-weight: 600; color: #16A34A;">LIVE</span>
        </div>
      </div>

      <!-- Stylised world map grid -->
      <div style="position: relative; background: linear-gradient(180deg, #F0F7FF 0%, #F9FAFB 100%); padding: 24px; min-height: 280px; overflow: hidden;">
        <!-- Grid lines -->
        <div style="position: absolute; inset: 0; opacity: 0.15;">
          <svg width="100%" height="100%" xmlns="http://www.w3.org/2000/svg">
            <defs><pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse"><path d="M 40 0 L 0 0 0 40" fill="none" stroke="#0066CC" stroke-width="0.5"/></pattern></defs>
            <rect width="100%" height="100%" fill="url(#grid)"/>
          </svg>
        </div>

        <!-- Threat dots -->
        <div *ngFor="let t of activeThreats; let i = index"
             [style.left.%]="t.lng"
             [style.top.%]="t.lat"
             style="position: absolute; transform: translate(-50%, -50%); z-index: 2;">
          <div [style.background]="severityColor(t.severity)"
               style="width: 12px; height: 12px; border-radius: 50%; animation: pulse 2s infinite; cursor: pointer; position: relative;">
            <div [style.background]="severityColor(t.severity)"
                 style="position: absolute; inset: -4px; border-radius: 50%; opacity: 0.3; animation: ping 2s cubic-bezier(0, 0, 0.2, 1) infinite;"></div>
          </div>
        </div>

        <!-- Region labels -->
        <span style="position: absolute; top: 20%; left: 22%; font-size: 0.65rem; color: #9CA3AF; font-weight: 600;">N. AMERICA</span>
        <span style="position: absolute; top: 18%; left: 52%; font-size: 0.65rem; color: #9CA3AF; font-weight: 600;">EUROPE</span>
        <span style="position: absolute; top: 28%; left: 70%; font-size: 0.65rem; color: #9CA3AF; font-weight: 600;">ASIA</span>
        <span style="position: absolute; top: 65%; left: 35%; font-size: 0.65rem; color: #9CA3AF; font-weight: 600;">S. AMERICA</span>
        <span style="position: absolute; top: 55%; left: 55%; font-size: 0.65rem; color: #9CA3AF; font-weight: 600;">AFRICA</span>
        <span style="position: absolute; top: 70%; left: 80%; font-size: 0.65rem; color: #9CA3AF; font-weight: 600;">OCEANIA</span>
      </div>

      <!-- Bottom legend -->
      <div style="padding: 12px 20px; border-top: 1px solid #E5E7EB; display: flex; gap: 16px; flex-wrap: wrap; align-items: center;">
        <div style="display: flex; align-items: center; gap: 6px;"><span style="width: 10px; height: 10px; border-radius: 50%; background: #DC2626;"></span><span style="font-size: 0.7rem; color: #6B7280;">Critical</span></div>
        <div style="display: flex; align-items: center; gap: 6px;"><span style="width: 10px; height: 10px; border-radius: 50%; background: #F59E0B;"></span><span style="font-size: 0.7rem; color: #6B7280;">High</span></div>
        <div style="display: flex; align-items: center; gap: 6px;"><span style="width: 10px; height: 10px; border-radius: 50%; background: #0066CC;"></span><span style="font-size: 0.7rem; color: #6B7280;">Medium</span></div>
        <div style="display: flex; align-items: center; gap: 6px;"><span style="width: 10px; height: 10px; border-radius: 50%; background: #6B7280;"></span><span style="font-size: 0.7rem; color: #6B7280;">Low</span></div>
        <span style="margin-left: auto; font-size: 0.7rem; font-weight: 600; color: #1A1A1A;">{{ activeThreats.length }} active threats</span>
      </div>
    </div>
  `,
  styles: [`
    @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.6; } }
    @keyframes ping { 75%, 100% { transform: scale(2.5); opacity: 0; } }
  `]
})
export class ThreatMapComponent implements OnInit, OnDestroy {
  activeThreats: GeoThreat[] = [];
  private interval: any;
  private idCounter = 0;

  private pool: Omit<GeoThreat, 'id' | 'timestamp'>[] = [
    { lat: 35, lng: 18, city: 'New York', country: 'US', type: 'Frida Injection', severity: 'Critical' },
    { lat: 25, lng: 52, city: 'London', country: 'UK', type: 'Root Detection', severity: 'High' },
    { lat: 30, lng: 75, city: 'Mumbai', country: 'IN', type: 'Repackaging', severity: 'Critical' },
    { lat: 22, lng: 82, city: 'Beijing', country: 'CN', type: 'SSL Bypass', severity: 'High' },
    { lat: 40, lng: 14, city: 'Toronto', country: 'CA', type: 'Memory Spoofing', severity: 'Medium' },
    { lat: 20, lng: 60, city: 'Frankfurt', country: 'DE', type: 'Bot Attack', severity: 'High' },
    { lat: 32, lng: 85, city: 'Tokyo', country: 'JP', type: 'Debugger', severity: 'Medium' },
    { lat: 60, lng: 30, city: 'São Paulo', country: 'BR', type: 'Hooking', severity: 'Critical' },
    { lat: 50, lng: 55, city: 'Lagos', country: 'NG', type: 'Emulator', severity: 'Low' },
    { lat: 75, lng: 82, city: 'Sydney', country: 'AU', type: 'Screen Capture', severity: 'Medium' },
  ];

  ngOnInit(): void {
    for (let i = 0; i < 6; i++) this.addRandomThreat();
    this.interval = setInterval(() => this.addRandomThreat(), 3000);
  }

  ngOnDestroy(): void {
    clearInterval(this.interval);
  }

  severityColor(s: string): string {
    return s === 'Critical' ? '#DC2626' : s === 'High' ? '#F59E0B' : s === 'Medium' ? '#0066CC' : '#6B7280';
  }

  private addRandomThreat(): void {
    const src = this.pool[Math.floor(Math.random() * this.pool.length)];
    const jitter = () => (Math.random() - 0.5) * 8;
    this.activeThreats.push({
      ...src,
      id: `t-${this.idCounter++}`,
      lat: Math.max(5, Math.min(90, src.lat + jitter())),
      lng: Math.max(5, Math.min(95, src.lng + jitter())),
      timestamp: new Date().toISOString()
    });
    if (this.activeThreats.length > 20) this.activeThreats.shift();
  }
}

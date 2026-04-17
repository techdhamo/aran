import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { IonicModule } from '@ionic/angular';
import { HttpClient } from '@angular/common/http';

interface WafPolicyStats {
  criticalThreat: number;
  apkIntegrity: number;
  stepUpRedirect: number;
  sandboxRoute: number;
  clean: number;
  total: number;
}

@Component({
  selector: 'app-waf-policy-breakdown',
  standalone: true,
  imports: [CommonModule, IonicModule],
  template: `
    <div style="background: #FFFFFF; border-radius: 12px; border: 1px solid #E5E7EB; overflow: hidden;">
      <div style="padding: 16px 20px; border-bottom: 1px solid #E5E7EB;">
        <h2 style="font-size: 1rem; font-weight: 700; color: #1A1A1A; margin: 0;">WAF Policy Breakdown</h2>
        <p style="font-size: 0.75rem; color: #6B7280; margin: 4px 0 0;">SCG RaspPolicyRoutingFilter decisions (last 24h)</p>
      </div>

      <div style="padding: 20px;">
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 16px;">
          <!-- CRITICAL_THREAT -->
          <div style="background: #FEF2F2; border: 1px solid #FCA5A5; border-radius: 8px; padding: 16px;">
            <div style="font-size: 0.7rem; font-weight: 600; color: #991B1B; margin-bottom: 8px;">CRITICAL_THREAT</div>
            <div style="font-size: 1.5rem; font-weight: 700; color: #DC2626;">{{ stats.criticalThreat }}</div>
            <div style="font-size: 0.7rem; color: #991B1B; margin-top: 4px;">{{ pct(stats.criticalThreat) }}%</div>
          </div>

          <!-- APK_INTEGRITY -->
          <div style="background: #FFFBEB; border: 1px solid #FCD34D; border-radius: 8px; padding: 16px;">
            <div style="font-size: 0.7rem; font-weight: 600; color: #92400E; margin-bottom: 8px;">APK_INTEGRITY</div>
            <div style="font-size: 1.5rem; font-weight: 700; color: #D97706;">{{ stats.apkIntegrity }}</div>
            <div style="font-size: 0.7rem; color: #92400E; margin-top: 4px;">{{ pct(stats.apkIntegrity) }}%</div>
          </div>

          <!-- STEP_UP_REDIRECT -->
          <div style="background: #EFF6FF; border: 1px solid #93C5FD; border-radius: 8px; padding: 16px;">
            <div style="font-size: 0.7rem; font-weight: 600; color: #1E40AF; margin-bottom: 8px;">STEP_UP_REDIRECT</div>
            <div style="font-size: 1.5rem; font-weight: 700; color: #2563EB;">{{ stats.stepUpRedirect }}</div>
            <div style="font-size: 0.7rem; color: #1E40AF; margin-top: 4px;">{{ pct(stats.stepUpRedirect) }}%</div>
          </div>

          <!-- SANDBOX_ROUTE -->
          <div style="background: #F0FDF4; border: 1px solid #86EFAC; border-radius: 8px; padding: 16px;">
            <div style="font-size: 0.7rem; font-weight: 600; color: #166534; margin-bottom: 8px;">SANDBOX_ROUTE</div>
            <div style="font-size: 1.5rem; font-weight: 700; color: #16A34A;">{{ stats.sandboxRoute }}</div>
            <div style="font-size: 0.7rem; color: #166534; margin-top: 4px;">{{ pct(stats.sandboxRoute) }}%</div>
          </div>

          <!-- CLEAN -->
          <div style="background: #F9FAFB; border: 1px solid #E5E7EB; border-radius: 8px; padding: 16px;">
            <div style="font-size: 0.7rem; font-weight: 600; color: #374151; margin-bottom: 8px;">CLEAN</div>
            <div style="font-size: 1.5rem; font-weight: 700; color: #6B7280;">{{ stats.clean }}</div>
            <div style="font-size: 0.7rem; color: #374151; margin-top: 4px;">{{ pct(stats.clean) }}%</div>
          </div>
        </div>

        <!-- Total -->
        <div style="margin-top: 16px; padding-top: 16px; border-top: 1px solid #E5E7EB; display: flex; justify-content: space-between; align-items: center;">
          <span style="font-size: 0.8rem; color: #6B7280;">Total Requests</span>
          <span style="font-size: 1rem; font-weight: 700; color: #1A1A1A;">{{ stats.total }}</span>
        </div>
      </div>
    </div>
  `,
  styles: []
})
export class WafPolicyBreakdownComponent implements OnInit {
  stats: WafPolicyStats = {
    criticalThreat: 0,
    apkIntegrity: 0,
    stepUpRedirect: 0,
    sandboxRoute: 0,
    clean: 0,
    total: 0
  };
  private readonly METRICS_URL = 'http://localhost:8080/api/v1/gateway/metrics/waf-policy';
  private pollTimer: any;

  constructor(private http: HttpClient) {}

  ngOnInit(): void {
    this.loadStats();
    // Poll every 60 seconds for real-time updates
    this.pollTimer = setInterval(() => this.loadStats(), 60000);
  }

  ngOnDestroy(): void {
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
    }
  }

  private loadStats(): void {
    this.http.get<WafPolicyStats>(this.METRICS_URL).subscribe({
      next: (data) => {
        this.stats = {
          criticalThreat: data.criticalThreat,
          apkIntegrity: data.apkIntegrity,
          stepUpRedirect: data.stepUpRedirect,
          sandboxRoute: data.sandboxRoute,
          clean: data.clean,
          total: data.criticalThreat + data.apkIntegrity + data.stepUpRedirect + data.sandboxRoute + data.clean
        };
      },
      error: (err) => {
        console.error('[SOC] Failed to load WAF policy stats:', err);
        // Fall back to zeros or last known values
      }
    });
  }

  pct(value: number): number {
    if (this.stats.total === 0) return 0;
    return Math.round((value / this.stats.total) * 100);
  }
}

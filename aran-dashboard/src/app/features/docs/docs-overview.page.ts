import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { IonicModule } from '@ionic/angular';

@Component({
  selector: 'app-docs-overview',
  standalone: true,
  imports: [CommonModule, IonicModule],
  template: `
    <ion-content style="--background: #F9FAFB;">
    <div style="padding: 32px 24px; max-width: 800px; margin: 0 auto;">
      <h1 style="font-size: 2rem; font-weight: 800; color: #1A1A1A; margin-bottom: 8px;">RASP Overview</h1>
      <p style="color: #6B7280; font-size: 1rem; line-height: 1.6; margin-bottom: 32px;">
        Runtime Application Self-Protection (RASP) is a security technology built into an application's runtime environment.
        It detects and prevents real-time attacks by analysing the app's behaviour from within.
      </p>

      <h2 style="font-size: 1.25rem; font-weight: 700; color: #1A1A1A; margin-bottom: 12px;">How Aran RASP Works</h2>
      <ol style="color: #374151; font-size: 0.9375rem; line-height: 1.8; padding-left: 20px;">
        <li><strong>Embed:</strong> Integrate the Aran SDK into your iOS or Android project.</li>
        <li><strong>Detect:</strong> The SDK continuously monitors for jailbreak, rooting, tampering, hooking, and debugging.</li>
        <li><strong>Respond:</strong> Configurable threat actions — block, report, or invoke Scorched Earth protocol.</li>
        <li><strong>Monitor:</strong> All telemetry streams to the Aran Cloud dashboard in real-time.</li>
      </ol>

      <h2 style="font-size: 1.25rem; font-weight: 700; color: #1A1A1A; margin: 32px 0 12px;">Supported Platforms</h2>
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px;">
        <ion-card style="margin: 0; border-radius: 8px; border: 1px solid #E5E7EB;">
          <ion-card-content style="display: flex; align-items: center; gap: 12px;">
            <ion-icon name="logo-apple" style="font-size: 28px; color: #1A1A1A;"></ion-icon>
            <div>
              <strong style="color: #1A1A1A;">iOS</strong>
              <p style="margin: 0; font-size: 0.8rem; color: #6B7280;">Swift / Obj-C &middot; iOS 14+</p>
            </div>
          </ion-card-content>
        </ion-card>
        <ion-card style="margin: 0; border-radius: 8px; border: 1px solid #E5E7EB;">
          <ion-card-content style="display: flex; align-items: center; gap: 12px;">
            <ion-icon name="logo-android" style="font-size: 28px; color: #16A34A;"></ion-icon>
            <div>
              <strong style="color: #1A1A1A;">Android</strong>
              <p style="margin: 0; font-size: 0.8rem; color: #6B7280;">Kotlin / Java &middot; API 24+</p>
            </div>
          </ion-card-content>
        </ion-card>
      </div>
    </div>
    </ion-content>
  `
})
export class DocsOverviewPage {}

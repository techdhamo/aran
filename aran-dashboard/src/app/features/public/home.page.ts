import { Component, CUSTOM_ELEMENTS_SCHEMA, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { IonicModule } from '@ionic/angular';
import { CookieConsentPopupComponent } from '../../shared/components/cookie-consent-popup.component';
import { FooterComponent } from '../../shared/components/footer.component';

@Component({
  selector: 'app-home-page',
  standalone: true,
  imports: [CommonModule, IonicModule, CookieConsentPopupComponent, FooterComponent],
  schemas: [CUSTOM_ELEMENTS_SCHEMA],
  template: `
    <ion-content style="--background: #FFFFFF;">

    <!-- Hero Section -->
    <section style="padding: 80px 24px 64px; text-align: center; background: linear-gradient(180deg, #FFFFFF 0%, #F8FAFF 100%); margin-top: 64px;">
      <div style="max-width: 800px; margin: 0 auto;">
        <div style="display: inline-block; padding: 6px 16px; border-radius: 20px; background: rgba(0,102,204,0.08); margin-bottom: 20px;">
          <span style="font-size: 0.8rem; font-weight: 600; color: #0066CC; letter-spacing: 0.03em;">ARAN SECURITY SUITE</span>
        </div>
        <h1 style="font-size: 2.75rem; font-weight: 800; color: #1A1A1A; margin: 0 0 20px; line-height: 1.12;">
          Runtime Application Self-Protection
        </h1>
        <p style="font-size: 1.0625rem; color: #6B7280; margin: 0 auto 36px; line-height: 1.7; max-width: 680px;">
          Runtime Application Self-Protection detects hostile behavior from inside the app session.
          It closes visibility gaps left by perimeter tools by continuously validating code integrity,
          runtime behavior, and request authenticity.
        </p>
        <div style="display: flex; justify-content: center; gap: 14px; flex-wrap: wrap;">
          <a routerLink="/auth/login"
             style="display: inline-flex; align-items: center; gap: 8px; padding: 14px 32px; background: linear-gradient(135deg, #0066CC 0%, #0052A3 100%); color: #FFFFFF; border-radius: 10px; font-size: 0.9375rem; font-weight: 700; text-decoration: none; box-shadow: 0 4px 14px rgba(0,102,204,0.35); transition: all 0.2s ease; cursor: pointer;">
            <ion-icon name="rocket-outline" style="font-size: 18px;"></ion-icon>
            Start Free Trial
          </a>
          <a routerLink="/contact"
             style="display: inline-flex; align-items: center; gap: 8px; padding: 14px 32px; background: transparent; color: #1A1A1A; border: 2px solid #E5E7EB; border-radius: 10px; font-size: 0.9375rem; font-weight: 700; text-decoration: none; cursor: pointer;">
            <ion-icon name="person-outline" style="font-size: 18px;"></ion-icon>
            Talk to an Expert
          </a>
        </div>
      </div>
    </section>

    <!-- Feature Slider -->
    <section style="background: #FFFFFF; padding: 16px 24px 64px;">
      <div style="max-width: 1060px; margin: 0 auto;">
        <swiper-container
          slides-per-view="1"
          space-between="20"
          navigation="false"
          pagination="true"
          pagination-clickable="true"
          pagination-dynamic-bullets="true"
          loop="true"
          autoplay-delay="4000"
          autoplay-disable-on-interaction="false"
          breakpoints='{"520":{"slidesPerView":2},"800":{"slidesPerView":3}}'
          style="padding: 8px 44px 56px;"
        >
          <swiper-slide *ngFor="let feature of features">
            <div style="padding: 28px 22px; text-align: left; min-height: 200px;">
              <div [style.background]="feature.bg" style="width: 46px; height: 46px; border-radius: 12px; display: flex; align-items: center; justify-content: center; margin-bottom: 18px;">
                <ion-icon [name]="feature.icon" [style.color]="feature.color" style="font-size: 22px;"></ion-icon>
              </div>
              <h3 style="font-size: 1.0625rem; font-weight: 700; color: #1A1A1A; margin: 0 0 10px; line-height: 1.3;">{{ feature.title }}</h3>
              <p style="font-size: 0.84rem; color: #6B7280; line-height: 1.65; margin: 0;">{{ feature.description }}</p>
            </div>
          </swiper-slide>
        </swiper-container>
      </div>
    </section>

    <!-- Stats -->
    <section style="background: #F9FAFB; padding: 56px 24px; border-top: 1px solid #F3F4F6; border-bottom: 1px solid #F3F4F6;">
      <div style="max-width: 900px; margin: 0 auto; display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 32px; text-align: center;">
        <div *ngFor="let stat of stats">
          <p style="font-size: 2rem; font-weight: 800; color: #0066CC; margin: 0 0 4px;">{{ stat.value }}</p>
          <p style="font-size: 0.8rem; font-weight: 500; color: #6B7280; margin: 0;">{{ stat.label }}</p>
        </div>
      </div>
    </section>

    <!-- Trust Bar -->
    <section style="background: #FFFFFF; padding: 48px 24px; text-align: center;">
      <p style="color: #9CA3AF; font-size: 0.8rem; margin: 0 0 20px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em;">Trusted by enterprise teams worldwide</p>
      <div style="display: flex; justify-content: center; gap: 48px; flex-wrap: wrap; opacity: 0.35;">
        <span style="font-size: 1.25rem; font-weight: 700; color: #9CA3AF;">Fintech Co</span>
        <span style="font-size: 1.25rem; font-weight: 700; color: #9CA3AF;">HealthTech</span>
        <span style="font-size: 1.25rem; font-weight: 700; color: #9CA3AF;">GovCloud</span>
        <span style="font-size: 1.25rem; font-weight: 700; color: #9CA3AF;">AutoSafe</span>
        <span style="font-size: 1.25rem; font-weight: 700; color: #9CA3AF;">NeoBank</span>
      </div>
    </section>

    <!-- Bottom CTA -->
    <section style="background: linear-gradient(135deg, #0A1628 0%, #0F2440 100%); padding: 72px 24px; text-align: center;">
      <h2 style="font-size: 1.75rem; font-weight: 800; color: #FFFFFF; margin: 0 0 12px;">Ready to secure your apps?</h2>
      <p style="font-size: 1rem; color: rgba(255,255,255,0.65); margin: 0 auto 36px; max-width: 520px; line-height: 1.6;">
        Start your enterprise trial today. Integrate the Aran RASP SDK into your build pipeline and protect your applications against zero-day exploits and reverse engineering.
      </p>
      <div style="display: flex; justify-content: center; gap: 14px; flex-wrap: wrap;">
        <a routerLink="/auth/login"
           style="display: inline-flex; align-items: center; gap: 8px; padding: 14px 32px; background: #FFFFFF; color: #0066CC; border-radius: 10px; font-size: 0.9375rem; font-weight: 700; text-decoration: none; box-shadow: 0 4px 20px rgba(0,0,0,0.2); cursor: pointer;">
          <ion-icon name="rocket-outline" style="font-size: 18px;"></ion-icon>
          Start Free Trial
        </a>
        <a routerLink="/contact"
           style="display: inline-flex; align-items: center; gap: 8px; padding: 14px 32px; background: transparent; color: #FFFFFF; border: 2px solid rgba(255,255,255,0.3); border-radius: 10px; font-size: 0.9375rem; font-weight: 700; text-decoration: none; cursor: pointer;">
          <ion-icon name="person-outline" style="font-size: 18px;"></ion-icon>
          Talk to an Expert
        </a>
      </div>
    </section>

    <!-- Footer -->
    <app-footer></app-footer>

    <!-- Cookie Consent Popup -->
    <app-cookie-consent-popup></app-cookie-consent-popup>

    </ion-content>
  `,
  styles: [`
    swiper-container::part(bullet-active) {
      background: #0066CC;
      opacity: 1;
    }
    swiper-container::part(bullet) {
      background: #CBD5E1;
      opacity: 1;
    }
    a:hover {
      transform: translateY(-1px);
      filter: brightness(1.05);
    }
  `]
})
export class HomePage implements OnInit {
  ngOnInit() {
    // Component initialization logic
  }

  features = [
    { icon: 'shield-checkmark-outline', title: 'Device Compromise Controls', color: '#0066CC', bg: '#F0F7FF', description: 'Enforces policy for rooted/jailbroken devices, runtime hook frameworks, and unsafe environments to prevent high-risk access.' },
    { icon: 'hardware-chip-outline', title: 'Hardware Attestation', color: '#7C3AED', bg: '#F5F3FF', description: 'Leverages Apple Secure Enclave and Android StrongBox to mathematically prove device integrity prior to session establishment.' },
    { icon: 'lock-closed-outline', title: 'Zero-Knowledge TLS Pinning', color: '#0891B2', bg: '#ECFEFF', description: 'Cryptographic memory blinding ensures expected certificate hashes cannot be dumped from RAM by reverse engineers.' },
    { icon: 'code-slash-outline', title: 'Anti-Reverse Engineering', color: '#DC2626', bg: '#FEF2F2', description: 'Detects Frida, Substrate, Xposed and debugger attachments in real-time using native-layer inspection and process memory scanning.' },
    { icon: 'eye-off-outline', title: 'Screen &amp; Clipboard Guard', color: '#D97706', bg: '#FFFBEB', description: 'Prevents screenshots, screen recording, clipboard exfiltration, and overlay attacks on sensitive application screens.' },
    { icon: 'analytics-outline', title: 'Threat Telemetry Streaming', color: '#16A34A', bg: '#F0FDF4', description: 'Streams real-time threat events to the Aran Cloud SOC dashboard with polymorphic signature rotation for attacker evasion.' },
    { icon: 'finger-print-outline', title: 'Behavioral Biometrics', color: '#DB2777', bg: '#FDF2F8', description: 'Continuous user authentication via keystroke dynamics, touch pressure, and gesture patterns — no passwords required.' },
    { icon: 'cloud-outline', title: 'QUIC Phantom Channel', color: '#0066CC', bg: '#F0F7FF', description: 'Syncs runtime security config over HTTP/3 QUIC, bypassing TCP-based proxy intercepts like Burp Suite and Charles Proxy.' },
    { icon: 'swap-horizontal-outline', title: 'Polymorphic Signatures', color: '#7C3AED', bg: '#F5F3FF', description: 'Detection logic signatures rotate dynamically, preventing attackers from building stable bypass scripts against known patterns.' },
    { icon: 'globe-outline', title: 'Global Threat Intelligence', color: '#0891B2', bg: '#ECFEFF', description: 'Correlates device-level threats with global attack campaigns using Aran Cloud\'s real-time threat intelligence network.' },
    { icon: 'git-network-outline', title: 'SIEM &amp; SOC Forwarding', color: '#16A34A', bg: '#F0FDF4', description: 'One-click forwarding to Splunk, Datadog, QRadar, and Elastic — CEF, JSON, and ECS formats supported natively.' },
    { icon: 'construct-outline', title: 'Virtual Patching (WAAP)', color: '#DC2626', bg: '#FEF2F2', description: 'Deploy runtime WAF rules instantly without app updates. Block CVEs, SQLi, XSS, and OGNL injection at the edge.' }
  ];

  stats = [
    { value: '100%', label: 'Hardware Attestation' },
    { value: '< 1ms', label: 'Inline Execution Latency' },
    { value: 'End to End', label: 'Runtime Protection' },
    { value: '0-Day', label: 'Exploit Prevention' }
  ];
}

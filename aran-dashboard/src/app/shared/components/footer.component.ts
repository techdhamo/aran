import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { CookieConsentService } from '../services/cookie-consent.service';
import { CookiePreferencesModalComponent } from './cookie-preferences-modal.component';

@Component({
  selector: 'app-footer',
  standalone: true,
  imports: [CommonModule, CookiePreferencesModalComponent],
  template: `
    <footer class="footer">
      <div class="footer-content">
        <div class="footer-main">
          <p>&copy; 2026 Mazhai.org &middot; All rights reserved.</p>
        </div>
        
        <div class="footer-links" *ngIf="cookieConsentService.hasConsent()">
          <div class="cookie-section">
            <p class="cookie-text">
              This website uses essential cookies for security and functionality. Optional cookies help us analyze usage and personalize your experience. You can manage your preferences at any time.
            </p>
            <button class="manage-btn" (click)="managePreferences()">Manage Preferences</button>
          </div>
        </div>
      </div>
    </footer>

    <!-- Cookie Preferences Modal -->
    <app-cookie-preferences-modal 
      [(showModal)]="showPreferencesModal">
    </app-cookie-preferences-modal>
  `,
  styles: [`
    .footer {
      text-align: center;
      padding: 28px 16px;
      color: #6B7280;
      font-size: 0.8rem;
      background: #FFFFFF;
      border-top: 1px solid #E5E7EB;
    }

    .footer-content {
      max-width: 1200px;
      margin: 0 auto;
    }

    .footer-main {
      margin-bottom: 16px;
    }

    .footer-links {
      margin-top: 16px;
      padding-top: 16px;
      border-top: 1px solid #E5E7EB;
    }

    .cookie-section {
      max-width: 600px;
      margin: 0 auto;
    }

    .cookie-text {
      font-size: 0.75rem;
      color: #9CA3AF;
      line-height: 1.5;
      margin: 0 0 12px;
    }

    .manage-btn {
      background: #F3F4F6;
      color: #374151;
      border: 1px solid #D1D5DB;
      border-radius: 6px;
      padding: 8px 16px;
      font-size: 0.75rem;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.2s ease;
    }

    .manage-btn:hover {
      background: #E5E7EB;
    }
  `]
})
export class FooterComponent {
  showPreferencesModal = false;

  constructor(public cookieConsentService: CookieConsentService) {}

  managePreferences() {
    this.showPreferencesModal = true;
  }
}

import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { CookieConsentService, CookiePreferences } from '../services/cookie-consent.service';

@Component({
  selector: 'app-cookie-consent-popup',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div *ngIf="showPopup" class="cookie-consent-overlay">
      <div class="cookie-consent-content">
        <div class="cookie-header">
          <div class="cookie-info">
            <h3>Cookie Preferences</h3>
            <p>
              This website uses essential cookies for security and functionality. Optional cookies help us analyze usage and personalize your experience.
            </p>
          </div>
          <button class="close-btn" (click)="closePopup()">&times;</button>
        </div>
        
        <div class="cookie-categories">
          <div class="category">
            <label class="category-label">
              <input type="checkbox" [checked]="preferences.necessary" disabled>
              <span class="checkmark"></span>
              <div class="category-info">
                <strong>Essential</strong>
                <small>Required for security and basic functionality</small>
              </div>
            </label>
          </div>
          
          <div class="category">
            <label class="category-label">
              <input type="checkbox" [(ngModel)]="preferences.analytics">
              <span class="checkmark"></span>
              <div class="category-info">
                <strong>Analytics</strong>
                <small>Help us understand how you use our site</small>
              </div>
            </label>
          </div>
          
          <div class="category">
            <label class="category-label">
              <input type="checkbox" [(ngModel)]="preferences.functional">
              <span class="checkmark"></span>
              <div class="category-info">
                <strong>Functional</strong>
                <small>Remember your preferences and settings</small>
              </div>
            </label>
          </div>
          
          <div class="category">
            <label class="category-label">
              <input type="checkbox" [(ngModel)]="preferences.marketing">
              <span class="checkmark"></span>
              <div class="category-info">
                <strong>Marketing</strong>
                <small>Show relevant content and advertisements</small>
              </div>
            </label>
          </div>
        </div>
        
        <div class="cookie-actions">
          <button class="btn btn-secondary" (click)="savePreferences()">Save Preferences</button>
          <button class="btn btn-outline" (click)="rejectAll()">Reject Optional</button>
          <button class="btn btn-primary" (click)="acceptAll()">Accept All</button>
        </div>
      </div>
    </div>
  `,
  styles: [`
    .cookie-consent-overlay {
      position: fixed;
      bottom: 0;
      left: 0;
      right: 0;
      background: #1A1A1A;
      color: #FFFFFF;
      padding: 20px;
      z-index: 9999;
      box-shadow: 0 -4px 20px rgba(0,0,0,0.3);
      max-height: 80vh;
      overflow-y: auto;
    }

    .cookie-consent-content {
      max-width: 1200px;
      margin: 0 auto;
      display: flex;
      flex-direction: column;
      gap: 20px;
    }

    .cookie-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 20px;
    }

    .cookie-info {
      flex: 1;
    }

    .cookie-info h3 {
      margin: 0 0 8px;
      font-size: 1.1rem;
      font-weight: 600;
    }

    .cookie-info p {
      margin: 0;
      font-size: 0.9rem;
      line-height: 1.5;
      color: rgba(255,255,255,0.8);
    }

    .close-btn {
      background: none;
      border: none;
      color: #FFFFFF;
      font-size: 1.5rem;
      cursor: pointer;
      padding: 0;
      line-height: 1;
      opacity: 0.7;
      transition: opacity 0.2s ease;
    }

    .close-btn:hover {
      opacity: 1;
    }

    .cookie-categories {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
      gap: 16px;
    }

    .category-label {
      display: flex;
      align-items: flex-start;
      gap: 12px;
      cursor: pointer;
      padding: 12px;
      border-radius: 8px;
      transition: background 0.2s ease;
    }

    .category-label:hover {
      background: rgba(255,255,255,0.05);
    }

    .category-label input[type="checkbox"] {
      display: none;
    }

    .checkmark {
      width: 20px;
      height: 20px;
      border: 2px solid rgba(255,255,255,0.3);
      border-radius: 4px;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: all 0.2s ease;
      flex-shrink: 0;
      margin-top: 2px;
    }

    .category-label input[type="checkbox"]:checked + .checkmark {
      background: #0066CC;
      border-color: #0066CC;
    }

    .category-label input[type="checkbox"]:checked + .checkmark::after {
      content: '✓';
      color: white;
      font-size: 12px;
      font-weight: bold;
    }

    .category-label input[type="checkbox"]:disabled + .checkmark {
      background: #4B5563;
      border-color: #4B5563;
      opacity: 0.5;
    }

    .category-label input[type="checkbox"]:disabled:checked + .checkmark {
      background: #0066CC;
      border-color: #0066CC;
      opacity: 0.7;
    }

    .category-label input[type="checkbox"]:disabled:checked + .checkmark::after {
      content: '✓';
      color: white;
      font-size: 12px;
      font-weight: bold;
    }

    .category-info {
      flex: 1;
    }

    .category-info strong {
      display: block;
      font-size: 0.95rem;
      margin-bottom: 4px;
    }

    .category-info small {
      color: rgba(255,255,255,0.6);
      font-size: 0.8rem;
      line-height: 1.3;
    }

    .cookie-actions {
      display: flex;
      justify-content: flex-end;
      gap: 12px;
      flex-wrap: wrap;
    }

    .btn {
      border-radius: 6px;
      padding: 12px 24px;
      font-size: 0.9rem;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.2s ease;
      border: none;
      min-width: 120px;
    }

    .btn-primary {
      background: #0066CC;
      color: #FFFFFF;
    }

    .btn-secondary {
      background: transparent;
      color: #FFFFFF;
      border: 1px solid rgba(255,255,255,0.3);
    }

    .btn-outline {
      background: rgba(255,255,255,0.1);
      color: #FFFFFF;
      border: 1px solid rgba(255,255,255,0.2);
    }

    @media (max-width: 768px) {
      .cookie-header {
        flex-direction: column;
        gap: 12px;
      }

      .cookie-categories {
        grid-template-columns: 1fr;
      }

      .cookie-actions {
        justify-content: stretch;
      }

      .btn {
        flex: 1;
        text-align: center;
      }
    }
  `]
})
export class CookieConsentPopupComponent implements OnInit {
  showPopup = false;
  preferences: CookiePreferences = {
    necessary: true,
    analytics: false,
    marketing: false,
    functional: false
  };

  constructor(private cookieConsentService: CookieConsentService) {}

  ngOnInit() {
    if (!this.cookieConsentService.hasConsent()) {
      this.showPopup = true;
      // Load existing preferences if any
      const existing = this.cookieConsentService.getPreferences();
      if (existing) {
        this.preferences = { ...existing };
      }
    }
  }

  acceptAll() {
    this.preferences = {
      necessary: true,
      analytics: true,
      marketing: true,
      functional: true
    };
    this.savePreferences();
  }

  rejectAll() {
    this.preferences = {
      necessary: true, // Necessary cookies are always required
      analytics: false,
      marketing: false,
      functional: false
    };
    this.savePreferences();
  }

  savePreferences() {
    this.cookieConsentService.setConsent('accepted');
    this.cookieConsentService.setPreferences(this.preferences);
    this.showPopup = false;
  }

  closePopup() {
    this.showPopup = false;
  }
}

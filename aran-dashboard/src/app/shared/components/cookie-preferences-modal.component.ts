import { Component, Input, Output, EventEmitter } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { CookieConsentService, CookiePreferences } from '../services/cookie-consent.service';

@Component({
  selector: 'app-cookie-preferences-modal',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div *ngIf="showModal" class="modal-overlay" (click)="closeOnOverlay($event)">
      <div class="modal-content">
        <div class="modal-header">
          <h2>Cookie Preferences</h2>
          <button class="close-btn" (click)="closeModal()">&times;</button>
        </div>
        
        <div class="modal-body">
          <p class="modal-description">
            This website uses essential cookies for security and functionality. Optional cookies help us analyze usage and personalize your experience.
          </p>
          
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
        </div>
        
        <div class="modal-footer">
          <button class="btn btn-secondary" (click)="rejectAll()">Reject Optional</button>
          <button class="btn btn-primary" (click)="savePreferences()">Save Preferences</button>
        </div>
      </div>
    </div>
  `,
  styles: [`
    .modal-overlay {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0, 0, 0, 0.5);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 10000;
      padding: 20px;
    }

    .modal-content {
      background: #FFFFFF;
      border-radius: 12px;
      max-width: 600px;
      width: 100%;
      max-height: 90vh;
      overflow-y: auto;
      box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
    }

    .modal-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 24px 24px 16px;
      border-bottom: 1px solid #E5E7EB;
    }

    .modal-header h2 {
      margin: 0;
      font-size: 1.5rem;
      font-weight: 700;
      color: #1A1A1A;
    }

    .close-btn {
      background: none;
      border: none;
      color: #6B7280;
      font-size: 1.5rem;
      cursor: pointer;
      padding: 0;
      line-height: 1;
      transition: color 0.2s ease;
    }

    .close-btn:hover {
      color: #1A1A1A;
    }

    .modal-body {
      padding: 24px;
    }

    .modal-description {
      color: #6B7280;
      line-height: 1.6;
      margin: 0 0 24px;
    }

    .cookie-categories {
      display: flex;
      flex-direction: column;
      gap: 16px;
    }

    .category-label {
      display: flex;
      align-items: flex-start;
      gap: 12px;
      cursor: pointer;
      padding: 16px;
      border: 1px solid #E5E7EB;
      border-radius: 8px;
      transition: all 0.2s ease;
    }

    .category-label:hover {
      background: #F9FAFB;
      border-color: #D1D5DB;
    }

    .category-label input[type="checkbox"] {
      display: none;
    }

    .checkmark {
      width: 20px;
      height: 20px;
      border: 2px solid #D1D5DB;
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
      background: #F3F4F6;
      border-color: #D1D5DB;
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
      color: #1A1A1A;
    }

    .category-info small {
      color: #6B7280;
      font-size: 0.8rem;
      line-height: 1.3;
    }

    .modal-footer {
      display: flex;
      justify-content: flex-end;
      gap: 12px;
      padding: 16px 24px 24px;
      border-top: 1px solid #E5E7EB;
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

    .btn-primary:hover {
      background: #0052A3;
    }

    .btn-secondary {
      background: #F3F4F6;
      color: #374151;
      border: 1px solid #D1D5DB;
    }

    .btn-secondary:hover {
      background: #E5E7EB;
    }

    @media (max-width: 640px) {
      .modal-overlay {
        padding: 0;
      }

      .modal-content {
        border-radius: 0;
        height: 100vh;
        max-height: 100vh;
      }

      .modal-footer {
        flex-direction: column;
      }

      .btn {
        width: 100%;
      }
    }
  `]
})
export class CookiePreferencesModalComponent {
  @Input() showModal = false;
  preferences: CookiePreferences = {
    necessary: true,
    analytics: false,
    marketing: false,
    functional: false
  };

  @Output() showModalChange = new EventEmitter<boolean>();

  constructor(private cookieConsentService: CookieConsentService) {}

  ngOnInit() {
    this.loadPreferences();
  }

  loadPreferences() {
    const existing = this.cookieConsentService.getPreferences();
    if (existing) {
      this.preferences = { ...existing };
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
      necessary: true,
      analytics: false,
      marketing: false,
      functional: false
    };
    this.savePreferences();
  }

  savePreferences() {
    this.cookieConsentService.setConsent('accepted');
    this.cookieConsentService.setPreferences(this.preferences);
    this.closeModal();
  }

  closeModal() {
    this.showModalChange.emit(false);
  }

  closeOnOverlay(event: MouseEvent) {
    if (event.target === event.currentTarget) {
      this.closeModal();
    }
  }
}

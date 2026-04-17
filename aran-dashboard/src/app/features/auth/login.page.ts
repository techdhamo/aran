import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { IonicModule } from '@ionic/angular';
import { AuthService } from '../../core/services/auth.service';

@Component({
  selector: 'app-login-page',
  standalone: true,
  imports: [CommonModule, FormsModule, IonicModule],
  template: `
    <ion-content style="--background: #F9FAFB;">
      <div style="min-height: 100%; display: flex; align-items: center; justify-content: center; padding: 24px;">
        <div style="background: #FFFFFF; border-radius: 16px; box-shadow: 0 4px 24px rgba(0,0,0,0.08); border: 1px solid #E5E7EB; width: 100%; max-width: 420px; overflow: hidden;">

          <!-- Card Header -->
          <div style="background: #FFFFFF; padding: 40px 32px 32px; text-align: center; border-bottom: 1px solid #F3F4F6;">
            <div style="width: 72px; height: 72px; background: #F9FAFB; border-radius: 50%; margin: 0 auto 20px; display: flex; align-items: center; justify-content: center; border: 1px solid #E5E7EB;">
              <img src="assets/icon/logo.png" alt="Aran" style="height: 48px; width: auto; object-fit: contain;" />
            </div>
            <h1 style="color: #1A1A1A; font-size: 1.75rem; font-weight: 800; margin: 0 0 8px; letter-spacing: -0.025em;">Aran Security Suite</h1>
            <p style="color: #6B7280; font-size: 0.9375rem; margin: 0; font-weight: 500;">Enterprise RASP Platform</p>
          </div>

          <!-- Form Body — NATIVE HTML INPUTS (bypass Shadow DOM) -->
          <div style="padding: 32px 24px;">
            <form (ngSubmit)="onSubmit()">
              <div style="margin-bottom: 20px;">
                <label for="email" style="display: block; font-size: 0.875rem; font-weight: 600; color: #1A1A1A; margin-bottom: 6px;">
                  Email Address
                </label>
                <input
                  id="email"
                  type="email"
                  [(ngModel)]="email"
                  name="email"
                  placeholder="you@company.com"
                  required
                  autocomplete="email"
                  style="width: 100%; padding: 12px 16px; border: 2px solid #E5E7EB; border-radius: 8px; font-size: 1rem; color: #1A1A1A; background: #FFFFFF; outline: none; transition: border-color 0.2s; box-sizing: border-box;"
                  (focus)="inputFocused=true"
                  (blur)="inputFocused=false"
                  [style.borderColor]="inputFocused ? '#0066CC' : '#E5E7EB'"
                />
              </div>

              <button
                type="submit"
                [disabled]="!email || !isValidEmail(email)"
                style="width: 100%; padding: 14px; background: linear-gradient(135deg, #0066CC 0%, #0052A3 100%); color: #FFFFFF; border: none; border-radius: 8px; font-size: 1rem; font-weight: 600; cursor: pointer; transition: opacity 0.2s; box-sizing: border-box;"
                [style.opacity]="!email || !isValidEmail(email) ? '0.5' : '1'"
              >
                Sign In Securely
              </button>
            </form>

            <!-- Security Features -->
            <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-top: 24px;">
              <div style="text-align: center; padding: 12px 8px; background: #F0F9FF; border-radius: 8px; border: 1px solid #E0F2FE;">
                <ion-icon name="shield-checkmark-outline" style="font-size: 1.25rem; color: #0066CC; display: block; margin: 0 auto 4px;"></ion-icon>
                <span style="font-size: 0.7rem; font-weight: 600; color: #0369A1;">Encrypted</span>
              </div>
              <div style="text-align: center; padding: 12px 8px; background: #F0F9FF; border-radius: 8px; border: 1px solid #E0F2FE;">
                <ion-icon name="finger-print-outline" style="font-size: 1.25rem; color: #0066CC; display: block; margin: 0 auto 4px;"></ion-icon>
                <span style="font-size: 0.7rem; font-weight: 600; color: #0369A1;">Biometric</span>
              </div>
              <div style="text-align: center; padding: 12px 8px; background: #F0F9FF; border-radius: 8px; border: 1px solid #E0F2FE;">
                <ion-icon name="time-outline" style="font-size: 1.25rem; color: #0066CC; display: block; margin: 0 auto 4px;"></ion-icon>
                <span style="font-size: 0.7rem; font-weight: 600; color: #0369A1;">Real-time</span>
              </div>
            </div>
          </div>

          <!-- Footer -->
          <div style="padding: 16px 24px; border-top: 1px solid #E5E7EB; text-align: center; background: #F9FAFB;">
            <span style="font-size: 0.8rem; color: #6B7280;">&copy; 2026 Mazhai.org</span>
          </div>
        </div>
      </div>
    </ion-content>
  `
})
export class LoginPage {
  email = '';
  inputFocused = false;
  private router = inject(Router);
  private auth = inject(AuthService);

  isValidEmail(email: string): boolean {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  }

  onSubmit(): void {
    if (!this.email || !this.isValidEmail(this.email)) return;
    this.auth.login(this.email);
    this.router.navigateByUrl('/dashboard/overview');
  }
}

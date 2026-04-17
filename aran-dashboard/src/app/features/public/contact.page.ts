import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { IonicModule } from '@ionic/angular';
import { RouterModule } from '@angular/router';

@Component({
  selector: 'app-contact-page',
  standalone: true,
  imports: [CommonModule, FormsModule, IonicModule, RouterModule],
  template: `
    <ion-content style="--background: #FFFFFF;">
      <div style="min-height: 100vh; display: flex; flex-direction: column;">
        
        <!-- Hero Section -->
        <section style="padding: 120px 24px 80px; text-align: center; background: linear-gradient(180deg, #FFFFFF 0%, #F8FAFF 100%); margin-top: 64px;">
          <div style="max-width: 800px; margin: 0 auto;">
            <div style="display: inline-block; padding: 6px 16px; border-radius: 20px; background: rgba(0,102,204,0.08); margin-bottom: 20px;">
              <span style="font-size: 0.8rem; font-weight: 600; color: #0066CC; letter-spacing: 0.03em;">CONTACT SALES</span>
            </div>
            <h1 style="font-size: 2.75rem; font-weight: 800; color: #1A1A1A; margin: 0 0 20px; line-height: 1.12;">
              Why Enterprises Choose Aran
            </h1>
            <p style="font-size: 1.0625rem; color: #6B7280; margin: 0 auto 36px; line-height: 1.7; max-width: 680px;">
              Runtime Application Self-Protection that defends mobile applications from the inside out. 
              Protect your fleet with deterministic security that works at scale.
            </p>
          </div>
        </section>

        <!-- Value Propositions -->
        <section style="padding: 80px 24px; background: #FFFFFF;">
          <div style="max-width: 1200px; margin: 0 auto;">
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 48px;">
              
              <div style="text-align: left;">
                <div style="width: 48px; height: 48px; background: rgba(0,102,204,0.1); border-radius: 12px; display: flex; align-items: center; justify-content: center; margin-bottom: 20px;">
                  <ion-icon name="shield-checkmark-outline" style="font-size: 24px; color: #0066CC;"></ion-icon>
                </div>
                <h3 style="font-size: 1.5rem; font-weight: 700; color: #1A1A1A; margin: 0 0 12px;">Zero-Trust Mobile Security</h3>
                <p style="font-size: 1rem; color: #6B7280; line-height: 1.6; margin: 0;">
                  Stay in your flow. Runtime protection that works silently in the background, 
                  defending against hooking frameworks, reverse engineering, and API abuse without disrupting user experience.
                </p>
              </div>

              <div style="text-align: left;">
                <div style="width: 48px; height: 48px; background: rgba(124,58,237,0.1); border-radius: 12px; display: flex; align-items: center; justify-content: center; margin-bottom: 20px;">
                  <ion-icon name="hardware-chip-outline" style="font-size: 24px; color: #7C3AED;"></ion-icon>
                </div>
                <h3 style="font-size: 1.5rem; font-weight: 700; color: #1A1A1A; margin: 0 0 12px;">Hardware-Rooted Trust</h3>
                <p style="font-size: 1rem; color: #6B7280; line-height: 1.6; margin: 0;">
                  Multiply your protection. Leverage Apple Secure Enclave and Android StrongBox 
                  to mathematically prove device integrity before establishing secure sessions.
                </p>
              </div>

              <div style="text-align: left;">
                <div style="width: 48px; height: 48px; background: rgba(16,163,74,0.1); border-radius: 12px; display: flex; align-items: center; justify-content: center; margin-bottom: 20px;">
                  <ion-icon name="analytics-outline" style="font-size: 24px; color: #16A34A;"></ion-icon>
                </div>
                <h3 style="font-size: 1.5rem; font-weight: 700; color: #1A1A1A; margin: 0 0 12px;">Accelerate Security ROI</h3>
                <p style="font-size: 1rem; color: #6B7280; line-height: 1.6; margin: 0;">
                  Stop mobile security sprawl. Centralize runtime protection across your entire mobile fleet 
                  with real-time threat telemetry and SIEM integration.
                </p>
              </div>
            </div>
          </div>
        </section>

        <!-- Contact Form Section -->
        <section style="padding: 80px 24px; background: #F9FAFB;">
          <div style="max-width: 600px; margin: 0 auto; text-align: center;">
            <h2 style="font-size: 2rem; font-weight: 800; color: #1A1A1A; margin: 0 0 16px;">Contact Sales</h2>
            <p style="font-size: 1.125rem; color: #6B7280; margin: 0 0 48px; line-height: 1.6;">
              Learn how to safely accelerate mobile security adoption across your organization.
            </p>

            <div style="background: #FFFFFF; border-radius: 16px; padding: 48px; box-shadow: 0 4px 24px rgba(0,0,0,0.08); border: 1px solid #E5E7EB;">
              <form (ngSubmit)="onSubmit()">
                <div style="margin-bottom: 24px; text-align: left;">
                  <label for="name" style="display: block; font-size: 0.875rem; font-weight: 600; color: #1A1A1A; margin-bottom: 8px;">
                    Full Name*
                  </label>
                  <input
                    id="name"
                    type="text"
                    [(ngModel)]="contactForm.name"
                    name="name"
                    placeholder="John Doe"
                    required
                    style="width: 100%; padding: 14px 16px; border: 2px solid #E5E7EB; border-radius: 8px; font-size: 1rem; color: #1A1A1A; background: #FFFFFF; outline: none; transition: border-color 0.2s; box-sizing: border-box;"
                    (focus)="inputFocused = 'name'"
                    (blur)="inputFocused = ''"
                    [style.borderColor]="inputFocused === 'name' ? '#0066CC' : '#E5E7EB'"
                  />
                </div>

                <div style="margin-bottom: 24px; text-align: left;">
                  <label for="email" style="display: block; font-size: 0.875rem; font-weight: 600; color: #1A1A1A; margin-bottom: 8px;">
                    Work Email*
                  </label>
                  <input
                    id="email"
                    type="email"
                    [(ngModel)]="contactForm.email"
                    name="email"
                    placeholder="john@company.com"
                    required
                    style="width: 100%; padding: 14px 16px; border: 2px solid #E5E7EB; border-radius: 8px; font-size: 1rem; color: #1A1A1A; background: #FFFFFF; outline: none; transition: border-color 0.2s; box-sizing: border-box;"
                    (focus)="inputFocused = 'email'"
                    (blur)="inputFocused = ''"
                    [style.borderColor]="inputFocused === 'email' ? '#0066CC' : '#E5E7EB'"
                  />
                </div>

                <div style="margin-bottom: 24px; text-align: left;">
                  <label for="company" style="display: block; font-size: 0.875rem; font-weight: 600; color: #1A1A1A; margin-bottom: 8px;">
                    Company*
                  </label>
                  <input
                    id="company"
                    type="text"
                    [(ngModel)]="contactForm.company"
                    name="company"
                    placeholder="Acme Corporation"
                    required
                    style="width: 100%; padding: 14px 16px; border: 2px solid #E5E7EB; border-radius: 8px; font-size: 1rem; color: #1A1A1A; background: #FFFFFF; outline: none; transition: border-color 0.2s; box-sizing: border-box;"
                    (focus)="inputFocused = 'company'"
                    (blur)="inputFocused = ''"
                    [style.borderColor]="inputFocused === 'company' ? '#0066CC' : '#E5E7EB'"
                  />
                </div>

                <div style="margin-bottom: 32px; text-align: left;">
                  <label for="message" style="display: block; font-size: 0.875rem; font-weight: 600; color: #1A1A1A; margin-bottom: 8px;">
                    How can we help?
                  </label>
                  <textarea
                    id="message"
                    [(ngModel)]="contactForm.message"
                    name="message"
                    placeholder="Tell us about your mobile security needs..."
                    rows="4"
                    style="width: 100%; padding: 14px 16px; border: 2px solid #E5E7EB; border-radius: 8px; font-size: 1rem; color: #1A1A1A; background: #FFFFFF; outline: none; transition: border-color 0.2s; resize: vertical; font-family: inherit; box-sizing: border-box;"
                    (focus)="inputFocused = 'message'"
                    (blur)="inputFocused = ''"
                    [style.borderColor]="inputFocused === 'message' ? '#0066CC' : '#E5E7EB'"
                  ></textarea>
                </div>

                <button
                  type="submit"
                  [disabled]="!isFormValid()"
                  style="width: 100%; padding: 16px; background: linear-gradient(135deg, #0066CC 0%, #0052A3 100%); color: #FFFFFF; border: none; border-radius: 8px; font-size: 1rem; font-weight: 600; cursor: pointer; transition: opacity 0.2s; box-sizing: border-box;"
                  [style.opacity]="!isFormValid() ? '0.5' : '1'"
                >
                  Submit
                </button>
              </form>

              <p style="font-size: 0.875rem; color: #6B7280; margin-top: 24px; line-height: 1.5;">
                By clicking "Submit," you agree to our <a href="#" style="color: #0066CC; text-decoration: none;">Terms</a>.
              </p>
            </div>
          </div>
        </section>

        <!-- Success Message -->
        <div *ngIf="showSuccess" style="position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); background: #FFFFFF; padding: 32px; border-radius: 16px; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04); border: 1px solid #E5E7EB; text-align: center; z-index: 1000;">
          <div style="width: 48px; height: 48px; background: rgba(16,163,74,0.1); border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 16px;">
            <ion-icon name="checkmark-outline" style="font-size: 24px; color: #16A34A;"></ion-icon>
          </div>
          <h3 style="font-size: 1.25rem; font-weight: 700; color: #1A1A1A; margin: 0 0 8px;">Thank You!</h3>
          <p style="font-size: 1rem; color: #6B7280; margin: 0 0 24px;">Our team will be in touch within 24 hours.</p>
          <button (click)="showSuccess = false" style="padding: 12px 24px; background: #0066CC; color: #FFFFFF; border: none; border-radius: 6px; font-size: 0.875rem; font-weight: 600; cursor: pointer;">
            Close
          </button>
        </div>
      </div>
    </ion-content>
  `,
  styles: [`
    :host {
      display: block;
    }
  `]
})
export class ContactPage {
  contactForm = {
    name: '',
    email: '',
    company: '',
    message: ''
  };
  inputFocused = '';
  showSuccess = false;

  isFormValid(): boolean {
    return this.contactForm.name.trim() !== '' &&
           this.contactForm.email.trim() !== '' &&
           this.contactForm.company.trim() !== '' &&
           this.isValidEmail(this.contactForm.email);
  }

  isValidEmail(email: string): boolean {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  }

  onSubmit(): void {
    if (!this.isFormValid()) return;
    
    // Here you would typically send the form data to your backend
    console.log('Contact form submitted:', this.contactForm);
    
    // Show success message
    this.showSuccess = true;
    
    // Reset form
    this.contactForm = {
      name: '',
      email: '',
      company: '',
      message: ''
    };
  }
}

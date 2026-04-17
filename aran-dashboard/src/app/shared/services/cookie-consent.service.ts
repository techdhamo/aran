import { Injectable } from '@angular/core';

export interface CookiePreferences {
  necessary: boolean;
  analytics: boolean;
  marketing: boolean;
  functional: boolean;
}

@Injectable({
  providedIn: 'root'
})
export class CookieConsentService {
  private readonly CONSENT_KEY = 'cookieConsent';
  private readonly PREFERENCES_KEY = 'cookiePreferences';

  hasConsent(): boolean {
    return !!localStorage.getItem(this.CONSENT_KEY);
  }

  getConsent(): 'accepted' | 'rejected' | null {
    return localStorage.getItem(this.CONSENT_KEY) as 'accepted' | 'rejected' | null;
  }

  setConsent(consent: 'accepted' | 'rejected'): void {
    localStorage.setItem(this.CONSENT_KEY, consent);
  }

  getPreferences(): CookiePreferences | null {
    const stored = localStorage.getItem(this.PREFERENCES_KEY);
    return stored ? JSON.parse(stored) : null;
  }

  setPreferences(preferences: CookiePreferences): void {
    localStorage.setItem(this.PREFERENCES_KEY, JSON.stringify(preferences));
  }

  shouldUseCookies(category: keyof CookiePreferences): boolean {
    const consent = this.getConsent();
    if (consent === 'rejected') return false;
    if (consent === 'accepted') return true;
    
    const preferences = this.getPreferences();
    return preferences ? preferences[category] : false;
  }

  resetConsent(): void {
    localStorage.removeItem(this.CONSENT_KEY);
    localStorage.removeItem(this.PREFERENCES_KEY);
  }
}

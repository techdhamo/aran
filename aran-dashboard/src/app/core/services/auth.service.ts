import { Injectable } from '@angular/core';
import { BehaviorSubject } from 'rxjs';

import { UserRole } from '../enums/user-role.enum';
import { UserSession } from '../models/user-session.model';

@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly storageKey = 'aran.session';
  private readonly sessionSubject = new BehaviorSubject<UserSession | null>(this.restoreSession());

  readonly session$ = this.sessionSubject.asObservable();

  login(email: string): void {
    const token = `mock-jwt-${Date.now()}`;
    const role = this.resolveRole(email);
    const session: UserSession = { email, token, role };
    localStorage.setItem(this.storageKey, JSON.stringify(session));
    this.sessionSubject.next(session);
  }

  private resolveRole(email: string): UserRole {
    const adminEmails = ['admin@aran.mazhai.org', 'admin@mazhai.org'];
    if (adminEmails.includes(email.toLowerCase())) return UserRole.ADMIN;
    return UserRole.TENANT;
  }

  logout(): void {
    localStorage.removeItem(this.storageKey);
    this.sessionSubject.next(null);
  }

  isLoggedIn(): boolean {
    return !!this.sessionSubject.value?.token;
  }

  getRole(): UserRole {
    return this.sessionSubject.value?.role ?? UserRole.GUEST;
  }

  hasAnyRole(roles: UserRole[]): boolean {
    return roles.includes(this.getRole());
  }

  private restoreSession(): UserSession | null {
    const raw = localStorage.getItem(this.storageKey);
    if (!raw) return null;
    try {
      return JSON.parse(raw) as UserSession;
    } catch {
      localStorage.removeItem(this.storageKey);
      return null;
    }
  }
}

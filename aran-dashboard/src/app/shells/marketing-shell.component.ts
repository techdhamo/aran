import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { IonicModule } from '@ionic/angular';

@Component({
  selector: 'app-marketing-shell',
  standalone: true,
  imports: [CommonModule, RouterModule, IonicModule],
  template: `
    <ion-header class="ion-no-border">
      <ion-toolbar style="--background: #FFFFFF; --color: #1A1A1A; --min-height: 64px; border-bottom: 1px solid #E5E7EB; z-index: 100; position: relative;">
        <div style="display: flex; align-items: center; justify-content: space-between; padding: 0 24px; max-width: 1200px; margin: 0 auto; width: 100%;">
          <div style="display: flex; align-items: center; gap: 12px; cursor: pointer;" (click)="goHome()">
            <img src="assets/icon/logo.png" alt="Aran" style="height: 32px; width: auto; object-fit: contain;" />
            <span style="font-size: 1.25rem; font-weight: 700; color: #1A1A1A; letter-spacing: -0.025em;">Aran Security Suite</span>
          </div>
          <nav style="display: flex; align-items: center; gap: 8px;">
            <ion-button fill="clear" size="small" routerLink="/product" style="--color: #1A1A1A; font-weight: 500;">Product</ion-button>
            <ion-button fill="clear" size="small" routerLink="/docs" style="--color: #1A1A1A; font-weight: 500;">Docs</ion-button>
            <ion-button fill="solid" size="small" routerLink="/auth/login" color="primary" style="font-weight: 600;">Login</ion-button>
          </nav>
        </div>
      </ion-toolbar>
    </ion-header>

    <ion-router-outlet></ion-router-outlet>
  `
})
export class MarketingShellComponent {
  goHome(): void {
    if (window.location.hash !== '#/' && window.location.hash !== '') {
      window.location.hash = '#/';
    }
  }
}

import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { IonicModule } from '@ionic/angular';
import { AuthService } from '../core/services/auth.service';

@Component({
  selector: 'app-shell',
  standalone: true,
  imports: [CommonModule, RouterModule, IonicModule],
  template: `
    <ion-split-pane contentId="main-content" when="md">
      <!-- Sidebar -->
      <ion-menu contentId="main-content" side="start" menuId="app-menu" type="overlay">
        <ion-header class="ion-no-border">
          <ion-toolbar style="--background: #0066CC; --color: #FFFFFF;">
            <ion-title style="font-weight: 700; font-size: 1rem;">Aran Cloud</ion-title>
          </ion-toolbar>
        </ion-header>
        <ion-content style="--background: #F9FAFB;">
          <ion-list style="--ion-item-background: transparent; padding-top: 8px;">
            <ion-list-header style="font-size: 0.7rem; font-weight: 700; color: #9CA3AF; text-transform: uppercase; letter-spacing: 0.05em; min-height: 32px;">
              ThreatCast
            </ion-list-header>
            <ion-item button routerLink="/dashboard/overview" routerLinkActive="selected" style="--color: #374151; font-size: 0.875rem;">
              <ion-icon name="bar-chart-outline" slot="start" style="color: #0066CC;"></ion-icon>
              Dashboard
            </ion-item>

            <ion-list-header style="font-size: 0.7rem; font-weight: 700; color: #9CA3AF; text-transform: uppercase; letter-spacing: 0.05em; min-height: 32px; margin-top: 8px;">
              WAAP &amp; Admin
            </ion-list-header>
            <ion-item button routerLink="/admin/virtual-patching" routerLinkActive="selected" style="--color: #374151; font-size: 0.875rem;">
              <ion-icon name="shield-half-outline" slot="start" style="color: #0066CC;"></ion-icon>
              Virtual Patching
            </ion-item>
            <ion-item button routerLink="/integrations" routerLinkActive="selected" style="--color: #374151; font-size: 0.875rem;">
              <ion-icon name="git-network-outline" slot="start" style="color: #0066CC;"></ion-icon>
              SIEM Integrations
            </ion-item>

            <ion-list-header style="font-size: 0.7rem; font-weight: 700; color: #9CA3AF; text-transform: uppercase; letter-spacing: 0.05em; min-height: 32px; margin-top: 8px;">
              Help
            </ion-list-header>
            <ion-item button routerLink="/support" routerLinkActive="selected" style="--color: #374151; font-size: 0.875rem;">
              <ion-icon name="chatbubbles-outline" slot="start" style="color: #0066CC;"></ion-icon>
              Support
            </ion-item>
          </ion-list>
          <div style="position: absolute; bottom: 16px; left: 0; right: 0; padding: 0 16px;">
            <ion-button expand="block" fill="outline" color="danger" size="small" (click)="logout()">
              <ion-icon name="log-out-outline" slot="start"></ion-icon>
              Logout
            </ion-button>
          </div>
        </ion-content>
      </ion-menu>

      <!-- Main Content -->
      <div class="ion-page" id="main-content">
        <ion-header class="ion-no-border">
          <ion-toolbar style="--background: #FFFFFF; --color: #1A1A1A; --min-height: 64px; border-bottom: 1px solid #E5E7EB;">
            <div style="display: flex; align-items: center; justify-content: space-between; padding: 0 20px; width: 100%;">
              <div style="display: flex; align-items: center; gap: 12px;">
                <ion-menu-button color="primary"></ion-menu-button>
                <img src="assets/icon/logo.png" alt="Aran" style="height: 32px; width: auto; object-fit: contain;" />
                <span style="font-size: 1.25rem; font-weight: 700; color: #1A1A1A; letter-spacing: -0.025em;">Aran Security Suite</span>
              </div>
            </div>
          </ion-toolbar>
        </ion-header>
        <ion-router-outlet></ion-router-outlet>
      </div>
    </ion-split-pane>
  `,
  styles: [`
    ion-item.selected { --color: #0066CC; font-weight: 600; }
    .app-scroll-container {
      flex: 1;
      overflow-y: auto;
      background: #F9FAFB;
      -webkit-overflow-scrolling: touch;
    }
  `]
})
export class AppShellComponent {
  private auth = inject(AuthService);

  logout(): void {
    this.auth.logout();
    window.location.hash = '#/';
  }
}

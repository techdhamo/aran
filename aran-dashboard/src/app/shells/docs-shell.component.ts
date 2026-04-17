import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { IonicModule } from '@ionic/angular';

@Component({
  selector: 'app-docs-shell',
  standalone: true,
  imports: [CommonModule, RouterModule, IonicModule],
  template: `
    <ion-header class="ion-no-border">
      <ion-toolbar style="--background: #FFFFFF; --color: #1A1A1A; border-bottom: 1px solid #E5E7EB;">
        <ion-buttons slot="start">
          <ion-button routerLink="/" style="--color: #1A1A1A;">
            <ion-icon name="arrow-back-outline" slot="icon-only"></ion-icon>
          </ion-button>
        </ion-buttons>
        <ion-title style="font-weight: 700; font-size: 1.125rem;">Aran Documentation</ion-title>
      </ion-toolbar>
    </ion-header>

    <ion-split-pane contentId="docs-content" when="md">
      <!-- TOC Sidebar -->
      <ion-menu contentId="docs-content" side="start" menuId="docs-menu" type="overlay">
        <ion-content style="--background: #F9FAFB;">
          <ion-list style="--ion-item-background: transparent;">
            <ion-list-header style="font-weight: 700; color: #1A1A1A; font-size: 0.875rem; text-transform: uppercase; letter-spacing: 0.05em;">
              Table of Contents
            </ion-list-header>
            <ion-item button routerLink="/docs" routerLinkActive="selected" [routerLinkActiveOptions]="{exact: true}" style="--color: #374151; font-size: 0.875rem;">
              <ion-icon name="shield-checkmark-outline" slot="start" style="color: #0066CC;"></ion-icon>
              RASP Overview
            </ion-item>
            <ion-item button routerLink="/docs/integration" routerLinkActive="selected" style="--color: #374151; font-size: 0.875rem;">
              <ion-icon name="code-slash-outline" slot="start" style="color: #0066CC;"></ion-icon>
              SDK Integration
            </ion-item>
            <ion-item button routerLink="/docs/api" routerLinkActive="selected" style="--color: #374151; font-size: 0.875rem;">
              <ion-icon name="cloud-outline" slot="start" style="color: #0066CC;"></ion-icon>
              API Reference
            </ion-item>
          </ion-list>
        </ion-content>
      </ion-menu>

      <!-- Main Docs Content -->
      <ion-content id="docs-content" style="--background: #FFFFFF;">
        <ion-router-outlet></ion-router-outlet>
      </ion-content>
    </ion-split-pane>
  `,
  styles: [`
    ion-item.selected { --color: #0066CC; font-weight: 600; }
  `]
})
export class DocsShellComponent {}

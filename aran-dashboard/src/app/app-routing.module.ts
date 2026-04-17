import { NgModule } from '@angular/core';
import { PreloadAllModules, RouterModule, Routes } from '@angular/router';

import { MarketingShellComponent } from './shells/marketing-shell.component';
import { DocsShellComponent } from './shells/docs-shell.component';
import { AppShellComponent } from './shells/app-shell.component';
import { authGuard } from './core/guards/auth.guard';
import { roleGuard } from './core/guards/role.guard';
import { UserRole } from './core/enums/user-role.enum';

const routes: Routes = [
  // Marketing Shell — public pages
  {
    path: '',
    component: MarketingShellComponent,
    children: [
      {
        path: '',
        loadComponent: () => import('./features/public/home.page').then(m => m.HomePage)
      },
      {
        path: 'product',
        loadComponent: () => import('./features/public/home.page').then(m => m.HomePage)
      },
      {
        path: 'contact',
        loadComponent: () => import('./features/public/contact.page').then(m => m.ContactPage)
      }
    ]
  },
  // Login — standalone full-screen (no shell)
  {
    path: 'auth/login',
    loadComponent: () => import('./features/auth/login.page').then(m => m.LoginPage)
  },
  // Docs Shell
  {
    path: 'docs',
    component: DocsShellComponent,
    children: [
      {
        path: '',
        loadComponent: () => import('./features/docs/docs-overview.page').then(m => m.DocsOverviewPage)
      }
    ]
  },
  // App Shell — authenticated
  {
    path: 'dashboard',
    component: AppShellComponent,
    canActivate: [authGuard],
    children: [
      {
        path: 'overview',
        loadComponent: () => import('./features/dashboard/overview.page').then(m => m.DashboardOverviewPage)
      },
      { path: '', redirectTo: 'overview', pathMatch: 'full' }
    ]
  },
  {
    path: 'support',
    component: AppShellComponent,
    canActivate: [authGuard],
    children: [
      {
        path: '',
        loadComponent: () => import('./features/support/support.page').then(m => m.SupportPage)
      }
    ]
  },
  // Admin — Virtual Patching
  {
    path: 'admin/virtual-patching',
    component: AppShellComponent,
    canActivate: [roleGuard(UserRole.ADMIN)],
    children: [
      {
        path: '',
        loadComponent: () => import('./features/admin/virtual-patching.component').then(m => m.VirtualPatchingComponent)
      }
    ]
  },
  // Tenant — SIEM Integrations
  {
    path: 'integrations',
    component: AppShellComponent,
    canActivate: [authGuard],
    children: [
      {
        path: '',
        loadComponent: () => import('./features/tenant/integrations.component').then(m => m.IntegrationsComponent)
      }
    ]
  },
  // Fallback
  { path: '**', redirectTo: '' }
];

@NgModule({
  imports: [
    RouterModule.forRoot(routes, {
      preloadingStrategy: PreloadAllModules,
      useHash: true
    })
  ],
  exports: [RouterModule]
})
export class AppRoutingModule {}

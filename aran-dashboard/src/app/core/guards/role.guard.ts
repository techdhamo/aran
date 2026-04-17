import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { AuthService } from '../services/auth.service';
import { UserRole } from '../enums/user-role.enum';

export function roleGuard(...allowedRoles: UserRole[]): CanActivateFn {
  return () => {
    const auth = inject(AuthService);
    const router = inject(Router);
    if (!auth.isLoggedIn()) return router.createUrlTree(['/auth/login']);
    if (allowedRoles.length && !auth.hasAnyRole(allowedRoles)) {
      return router.createUrlTree(['/dashboard/overview']);
    }
    return true;
  };
}

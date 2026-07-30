// Route guard that blocks protected screens until client auth is available.
import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { catchError, map, of } from 'rxjs';
import { AuthService } from './auth';

// Restores a cookie-backed session when possible before redirecting to login.
export const authGuard: CanActivateFn = () => {
  const auth = inject(AuthService);
  const router = inject(Router);

  if (auth.isAuthenticated()) {
    return true;
  }

  return auth.refreshSession().pipe(
    map(() => true),
    catchError(() => of(router.createUrlTree(['/login']))),
  );
};

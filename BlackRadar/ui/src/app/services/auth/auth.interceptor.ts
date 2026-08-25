// HTTP interceptor that attaches auth tokens and refreshes expired sessions.
import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { catchError, switchMap, throwError } from 'rxjs';

import { environment } from '../../../environments/environment';
import { AuthService } from './auth';

// Adds the bearer token to API requests and retries once after a refresh.
export const authInterceptor: HttpInterceptorFn = (request, next) => {
  const authService = inject(AuthService);
  const router = inject(Router);
  const token = authService.getAccessToken();
  const isAuthEndpoint = request.url.startsWith(`${environment.apiUrl}/auth/`);

  const authenticatedRequest =
    token &&
    request.url.startsWith(environment.apiUrl) &&
    !isAuthEndpoint &&
    !request.headers.has('Authorization')
      ? request.clone({
          setHeaders: {
            Authorization: `Bearer ${token}`,
          },
        })
      : request;

  return next(authenticatedRequest).pipe(
    catchError((error: unknown) => {
      if (
        !(error instanceof HttpErrorResponse) ||
        error.status !== 401 ||
        !token ||
        isAuthEndpoint
      ) {
        if (error instanceof HttpErrorResponse && request.url.startsWith(environment.apiUrl)) {
          navigateForAPIError(router, error.status);
        }
        return throwError(() => error);
      }

      return authService.refreshSession().pipe(
        switchMap((session) =>
          next(
            request.clone({
              setHeaders: {
                Authorization: `Bearer ${session.token}`,
              },
            }),
          ),
        ),
        catchError((refreshError: unknown) => {
          if (refreshError instanceof HttpErrorResponse) {
            handleRefreshFailure(authService, router, refreshError.status);
          }
          return throwError(() => refreshError);
        }),
      );
    }),
  );
};

function navigateForAPIError(router: Router, status: number): void {
  if (status === 403) {
    void router.navigateByUrl('/access-denied');
    return;
  }
  if (status >= 500) {
    void router.navigateByUrl('/server-error');
  }
}

function handleRefreshFailure(authService: AuthService, router: Router, status: number): void {
  if (status === 401 || status === 403) {
    authService.clearSession();
    void router.navigateByUrl('/session-expired');
    return;
  }
  if (status >= 500) {
    void router.navigateByUrl('/server-error');
  }
}

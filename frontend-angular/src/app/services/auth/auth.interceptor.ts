// HTTP interceptor that attaches auth tokens and refreshes expired sessions.
import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { catchError, switchMap, throwError } from 'rxjs';

import { environment } from '../../../environments/environment';
import { AuthService } from './auth';

// Adds the bearer token to API requests and retries once after a refresh.
export const authInterceptor: HttpInterceptorFn = (request, next) => {
  const authService = inject(AuthService);
  const token = authService.getAccessToken();
  const isAuthEndpoint = request.url.startsWith(`${environment.apiUrl}/auth/`);

  const authenticatedRequest =
    token && request.url.startsWith(environment.apiUrl) && !isAuthEndpoint && !request.headers.has('Authorization')
      ? request.clone({
          setHeaders: {
            Authorization: `Bearer ${token}`,
          },
        })
      : request;

  return next(authenticatedRequest).pipe(
    catchError((error: unknown) => {
      if (!(error instanceof HttpErrorResponse) || error.status !== 401 || !token || isAuthEndpoint) {
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
          authService.logout();
          return throwError(() => refreshError);
        }),
      );
    }),
  );
};

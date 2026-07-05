// Authentication service for login, session persistence, and token refresh.
import { isPlatformBrowser } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { Inject, Injectable, PLATFORM_ID } from '@angular/core';
import { Observable, finalize, shareReplay, tap, throwError, timeout } from 'rxjs';

import { environment } from '../../../environments/environment';

export interface LoginRequest {
  userOrEmail: string;
  password: string;
}

export interface LoginResponse {
  user: {
    id: number;
    username: string;
    email: string;
  };
  token: string;
  tokenExpiresAt: string;
  refreshToken: string;
  refreshTokenExpiresAt: string;
}

export const authStorageKey = 'secureops.auth';

@Injectable({
  providedIn: 'root',
})
export class AuthService {
  private refreshRequest$: Observable<LoginResponse> | null = null;

  constructor(
    private readonly httpClient: HttpClient,
    @Inject(PLATFORM_ID) private readonly platformId: object,
  ) {}

  // Sends credentials to the backend login endpoint and stores the returned session.
  login(request: LoginRequest): Observable<LoginResponse> {
    return this.httpClient.post<LoginResponse>(`${environment.apiUrl}/auth/login`, request).pipe(
      timeout(15000),
      tap((response) => {
        this.saveSession(response);
      }),
    );
  }

  // Reports whether a usable session exists in browser storage.
  isAuthenticated(): boolean {
    if (!isPlatformBrowser(this.platformId)) {
      return false;
    }

    return this.readSession() !== null;
  }

  // Clears the saved session from browser storage.
  logout(): void {
    if (!isPlatformBrowser(this.platformId)) {
      return;
    }

    localStorage.removeItem(authStorageKey);
  }

  // Returns the saved login response when the app is running in a browser.
  getSession(): LoginResponse | null {
    if (!isPlatformBrowser(this.platformId)) {
      return null;
    }

    return this.readSession();
  }

  // Returns the current access token from the stored session.
  getAccessToken(): string | null {
    return this.getSession()?.token ?? null;
  }

  // Exchanges the stored refresh token for a new access token and session.
  refreshSession(): Observable<LoginResponse> {
    if (!isPlatformBrowser(this.platformId)) {
      return throwError(() => new Error('Refresh is only available in the browser.'));
    }

    const session = this.getSession();
    if (!session?.refreshToken) {
      return throwError(() => new Error('Missing refresh token.'));
    }

    if (!this.refreshRequest$) {
      const request$ = this.httpClient
        .post<LoginResponse>(`${environment.apiUrl}/auth/refresh`, { refreshToken: session.refreshToken })
        .pipe(
          timeout(15000),
          tap((response) => {
            this.saveSession(response);
          }),
          shareReplay({ bufferSize: 1, refCount: false }),
          finalize(() => {
            if (this.refreshRequest$ === request$) {
              this.refreshRequest$ = null;
            }
          }),
        );

      this.refreshRequest$ = request$;
    }

    return this.refreshRequest$;
  }

  // Persists the latest authenticated session in browser storage.
  private saveSession(session: LoginResponse): void {
    if (!isPlatformBrowser(this.platformId)) {
      return;
    }

    localStorage.setItem(authStorageKey, JSON.stringify(session));
  }

  // Reads and validates the stored session payload from browser storage.
  private readSession(): LoginResponse | null {
    const rawSession = localStorage.getItem(authStorageKey);
    if (!rawSession) {
      return null;
    }

    try {
      return JSON.parse(rawSession) as LoginResponse;
    } catch {
      localStorage.removeItem(authStorageKey);
      return null;
    }
  }
}

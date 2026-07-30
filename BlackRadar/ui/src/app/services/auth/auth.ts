// Authentication service for login, in-memory session state, and token refresh.
import { HttpClient } from '@angular/common/http';
import { Injectable, signal } from '@angular/core';
import { Observable, finalize, shareReplay, tap, timeout } from 'rxjs';

import { environment } from '../../../environments/environment';

export interface LoginRequest {
  userOrEmail: string;
  password: string;
}

export interface LoginResponse {
  user: {
    id: string;
    username: string;
    email: string;
    organization?: string;
  };
  token: string;
  tokenExpiresAt: string;
  refreshTokenExpiresAt: string;
}

@Injectable({
  providedIn: 'root',
})
export class AuthService {
  private refreshRequest$: Observable<LoginResponse> | null = null;
  readonly session = signal<LoginResponse | null>(null);

  constructor(private readonly httpClient: HttpClient) {}

  // Sends credentials to the backend login endpoint and stores the returned session.
  login(request: LoginRequest): Observable<LoginResponse> {
    return this.httpClient
      .post<LoginResponse>(`${environment.apiUrl}/auth/login`, request, { withCredentials: true })
      .pipe(
        timeout(15000),
        tap((response) => {
          this.saveSession(response);
        }),
      );
  }

  // Reports whether a usable in-memory session exists.
  isAuthenticated(): boolean {
    return this.session() !== null;
  }

  // Revokes the refresh session cookie and clears the in-memory session.
  logout(): Observable<void> {
    return this.httpClient.post<void>(`${environment.apiUrl}/auth/logout`, {}, { withCredentials: true }).pipe(
      timeout(15000),
      tap(() => {
        this.clearSession();
      }),
    );
  }

  // Clears the in-memory session without contacting the backend.
  clearSession(): void {
    this.session.set(null);
  }

  // Returns the current in-memory login response.
  getSession(): LoginResponse | null {
    return this.session();
  }

  // Returns the current access token from memory.
  getAccessToken(): string | null {
    return this.getSession()?.token ?? null;
  }

  // Exchanges the HttpOnly refresh cookie for a new access token and session.
  refreshSession(): Observable<LoginResponse> {
    if (!this.refreshRequest$) {
      const request$ = this.httpClient
        .post<LoginResponse>(`${environment.apiUrl}/auth/refresh`, {}, { withCredentials: true })
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

  // Stores the latest authenticated session in memory only.
  private saveSession(session: LoginResponse): void {
    this.session.set(session);
  }
}

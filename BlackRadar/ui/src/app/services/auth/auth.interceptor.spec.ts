import { HttpClient } from '@angular/common/http';
import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';

import { environment } from '../../../environments/environment';
import { AuthService } from './auth';
import { authInterceptor } from './auth.interceptor';

describe('authInterceptor', () => {
  let httpClient: HttpClient;
  let httpTestingController: HttpTestingController;
  let authService: AuthService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(withInterceptors([authInterceptor])), provideHttpClientTesting()],
    });

    httpClient = TestBed.inject(HttpClient);
    httpTestingController = TestBed.inject(HttpTestingController);
    authService = TestBed.inject(AuthService);
    authService.session.set({
      user: { id: 1, username: 'analyst', email: 'analyst@example.com', organization: 'Security' },
      token: 'token-123',
      tokenExpiresAt: new Date().toISOString(),
      refreshTokenExpiresAt: new Date().toISOString(),
    });
  });

  afterEach(() => {
    httpTestingController.verify();
  });

  it('should attach bearer token to api requests', () => {
    httpClient.get(`${environment.apiUrl}/assets`).subscribe();

    const request = httpTestingController.expectOne(`${environment.apiUrl}/assets`);
    expect(request.request.headers.get('Authorization')).toBe('Bearer token-123');
    request.flush([]);
  });

  it('should refresh and retry api requests after a 401 response', () => {
    httpClient.get(`${environment.apiUrl}/assets`).subscribe();

    const initialRequest = httpTestingController.expectOne(`${environment.apiUrl}/assets`);
    expect(initialRequest.request.headers.get('Authorization')).toBe('Bearer token-123');
    initialRequest.flush({ error: 'Unauthorized' }, { status: 401, statusText: 'Unauthorized' });

    const refreshRequest = httpTestingController.expectOne(`${environment.apiUrl}/auth/refresh`);
    expect(refreshRequest.request.body).toEqual({});
    expect(refreshRequest.request.withCredentials).toBe(true);
    refreshRequest.flush({
      user: { id: 1, username: 'analyst', email: 'analyst@example.com' },
      token: 'token-456',
      tokenExpiresAt: new Date().toISOString(),
      refreshTokenExpiresAt: new Date().toISOString(),
    });

    const retriedRequest = httpTestingController.expectOne(`${environment.apiUrl}/assets`);
    expect(retriedRequest.request.headers.get('Authorization')).toBe('Bearer token-456');
    retriedRequest.flush([]);
  });
});

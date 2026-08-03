import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';

import { environment } from '../../../environments/environment';
import { AuthService } from './auth';

describe('AuthService', () => {
  let service: AuthService;
  let httpTestingController: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(AuthService);
    httpTestingController = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpTestingController.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('stores the login response in memory after the refresh cookie is set', () => {
    service.login({ userOrEmail: 'analyst', password: 'Password1!' }).subscribe();

    const request = httpTestingController.expectOne(`${environment.apiUrl}/auth/login`);
    expect(request.request.withCredentials).toBe(true);
    request.flush(loginResponse());

    expect(service.getAccessToken()).toBe('access-token');
  });

  it('uses the refresh cookie without including a token in the request body', () => {
    service.refreshSession().subscribe();

    const request = httpTestingController.expectOne(`${environment.apiUrl}/auth/refresh`);
    expect(request.request.body).toEqual({});
    expect(request.request.withCredentials).toBe(true);
    request.flush(loginResponse());
  });

  it('clears the in-memory session after logout succeeds', () => {
    service.session.set(loginResponse());
    service.logout().subscribe();

    const request = httpTestingController.expectOne(`${environment.apiUrl}/auth/logout`);
    expect(request.request.body).toEqual({});
    expect(request.request.withCredentials).toBe(true);
    request.flush(null);

    expect(service.isAuthenticated()).toBe(false);
  });
});

function loginResponse() {
  return {
    user: {
      id: '00000000-0000-4000-8000-000000000001',
      fullName: 'Analyst User',
      username: 'analyst',
      email: 'analyst@example.com',
    },
    token: 'access-token',
    tokenExpiresAt: new Date().toISOString(),
    refreshTokenExpiresAt: new Date().toISOString(),
  };
}

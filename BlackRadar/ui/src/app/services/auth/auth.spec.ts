// Verifies in-memory authentication state, cookie-backed refresh, and logout behavior.
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';

import { environment } from '../../../environments/environment';
import { AuthService } from './auth';

describe('AuthService', () => {
  let service: AuthService;
  let httpTestingController: HttpTestingController;

  // Creates the authentication service test environment before each test.
  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(AuthService);
    httpTestingController = TestBed.inject(HttpTestingController);
  });

  // Confirms all expected HTTP requests were completed after each test.
  afterEach(() => {
    httpTestingController.verify();
  });

  // Confirms the authentication service can be created.
  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  // Confirms a successful login stores the access token in memory.
  it('stores the login response in memory after the refresh cookie is set', () => {
    service.login({ userOrEmail: 'analyst', password: 'Password1!' }).subscribe();

    const request = httpTestingController.expectOne(`${environment.apiUrl}/auth/login`);
    expect(request.request.withCredentials).toBe(true);
    request.flush(loginResponse());

    expect(service.getAccessToken()).toBe('access-token');
  });

  // Confirms refresh uses the HttpOnly cookie without sending a token in the body.
  it('uses the refresh cookie without including a token in the request body', () => {
    service.refreshSession().subscribe();

    const request = httpTestingController.expectOne(`${environment.apiUrl}/auth/refresh`);
    expect(request.request.body).toEqual({});
    expect(request.request.withCredentials).toBe(true);
    request.flush(loginResponse());
  });

  // Confirms logout clears the in-memory session after the backend succeeds.
  it('clears the in-memory session after logout succeeds', () => {
    service.session.set(loginResponse());
    service.logout().subscribe();

    const request = httpTestingController.expectOne(`${environment.apiUrl}/auth/logout`);
    expect(request.request.body).toEqual({});
    expect(request.request.withCredentials).toBe(true);
    request.flush(null);

    expect(service.isAuthenticated()).toBe(false);
  });

  it('updates the in-memory user after a profile update succeeds', () => {
    service.session.set(loginResponse());
    service
      .updateProfile({
        fullName: 'Updated User',
        username: 'updated',
        email: 'updated@example.com',
      })
      .subscribe();

    const request = httpTestingController.expectOne(`${environment.apiUrl}/profile`);
    expect(request.request.method).toBe('PUT');
    request.flush({
      id: '00000000-0000-0000-0000-000000000001',
      fullName: 'Updated User',
      username: 'updated',
      email: 'updated@example.com',
    });

    expect(service.getSession()?.user.username).toBe('updated');
  });
});

// Builds a representative authenticated login response for service tests.
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

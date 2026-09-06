// Verifies dashboard AI summaries remain scoped to the authenticated user.
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';

import { environment } from '../../../environments/environment';
import { AuthService } from '../auth/auth';
import { AIService, DashboardSummary } from './ai';

describe('AIService', () => {
  let service: AIService;
  let httpTestingController: HttpTestingController;
  const session = signal(loginResponse('user-a'));

  // Creates the AI service test environment before each test.
  beforeEach(() => {
    session.set(loginResponse('user-a'));
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: AuthService, useValue: { session } },
      ],
    });
    service = TestBed.inject(AIService);
    httpTestingController = TestBed.inject(HttpTestingController);
  });

  // Confirms all expected HTTP requests were completed after each test.
  afterEach(() => {
    httpTestingController.verify();
  });

  // Confirms a response is not exposed after the authenticated user changes.
  it('does not cache a dashboard summary when the authenticated user changes', () => {
    service.getDashboardSummary().subscribe();

    const request = httpTestingController.expectOne(`${environment.apiUrl}/dashboard/ai-summary`);
    session.set(loginResponse('user-b'));
    request.flush(dashboardSummary());

    expect(service.dashboardSummary()).toBeNull();
  });
});

// Builds an authenticated session for the supplied user ID.
function loginResponse(userId: string) {
  return {
    user: {
      id: userId,
      fullName: 'Analyst User',
      username: 'analyst',
      email: 'analyst@example.com',
    },
    token: 'access-token',
    tokenExpiresAt: new Date().toISOString(),
    refreshTokenExpiresAt: new Date().toISOString(),
  };
}

// Builds a valid provider response for dashboard-summary service tests.
function dashboardSummary(): DashboardSummary {
  return {
    headline: 'Review critical risk',
    overallAssessment: 'critical',
    summary: 'One critical finding requires attention.',
    priorityFindings: [],
    positiveObservations: [],
    uncertainties: [],
  };
}

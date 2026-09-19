// Verifies dashboard AI summaries are loaded from and refreshed through the backend.
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';

import { environment } from '../../../environments/environment';
import { AIService, DashboardSummary } from './ai';

describe('AIService', () => {
  let service: AIService;
  let httpTestingController: HttpTestingController;

  // Creates the AI service test environment before each test.
  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(AIService);
    httpTestingController = TestBed.inject(HttpTestingController);
  });

  // Confirms all expected HTTP requests were completed after each test.
  afterEach(() => {
    httpTestingController.verify();
  });

  it('loads the organization summary without using the POST refresh endpoint', () => {
    service.loadDashboardSummary().subscribe();

    const request = httpTestingController.expectOne({
      method: 'GET',
      url: `${environment.apiUrl}/dashboard/ai-summary`,
    });
    request.flush(dashboardSummary());

    expect(service.dashboardSummary()?.summaryId).toBe('summary-1');
  });

  it('uses the server-generated timestamp when refreshing a summary', () => {
    service.getDashboardSummary().subscribe();

    const request = httpTestingController.expectOne({
      method: 'POST',
      url: `${environment.apiUrl}/dashboard/ai-summary`,
    });
    request.flush(dashboardSummary());

    expect(service.dashboardSummary()?.generatedAt).toBe('2026-09-07T09:15:00.000Z');
  });
});

// Builds a valid provider response for dashboard-summary service tests.
function dashboardSummary(): DashboardSummary {
  return {
    summaryId: 'summary-1',
    headline: 'Review critical risk',
    overallAssessment: 'critical',
    summary: 'One critical finding requires attention.',
    generatedAt: '2026-09-07T09:15:00.000Z',
    priorityFindings: [],
    positiveObservations: [],
    uncertainties: [],
  };
}

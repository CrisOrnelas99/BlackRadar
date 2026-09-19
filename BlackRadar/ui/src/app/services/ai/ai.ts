// Requests backend-generated, authenticated AI explanations for dashboard data.
import { HttpClient } from '@angular/common/http';
import { computed, Injectable, signal } from '@angular/core';
import { tap } from 'rxjs';

import { environment } from '../../../environments/environment';

export interface DashboardFinding {
  priority: number;
  assetId: string;
  assetName: string;
  vulnerabilityId: string;
  cveId: string;
  explanation: string;
  riskReason: string;
  recommendedNextStep: string;
}

export interface DashboardSummary {
  summaryId: string;
  headline: string;
  overallAssessment: 'low' | 'medium' | 'high' | 'critical';
  summary: string;
  generatedAt: string;
  priorityFindings: DashboardFinding[];
  positiveObservations: string[];
  uncertainties: string[];
}

@Injectable({
  providedIn: 'root',
})
export class AIService {
  private readonly cachedDashboardSummary = signal<DashboardSummary | null>(null);
  readonly dashboardSummary = computed(() => this.cachedDashboardSummary());

  // Creates the service with the shared authenticated HTTP client.
  constructor(private readonly httpClient: HttpClient) {}

  // Loads the latest organization summary without calling the AI provider.
  loadDashboardSummary() {
    this.cachedDashboardSummary.set(null);
    return this.httpClient
      .get<DashboardSummary>(`${environment.apiUrl}/dashboard/ai-summary`)
      .pipe(tap((summary) => this.cachedDashboardSummary.set(summary)));
  }

  // Requests a fresh backend-grounded explanation for the current dashboard data.
  getDashboardSummary() {
    return this.httpClient
      .post<DashboardSummary>(`${environment.apiUrl}/dashboard/ai-summary`, {})
      .pipe(tap((summary) => this.cachedDashboardSummary.set(summary)));
  }
}

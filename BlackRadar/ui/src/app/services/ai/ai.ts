// Requests backend-generated, authenticated AI explanations for dashboard data.
import { HttpClient } from '@angular/common/http';
import { computed, Injectable, signal } from '@angular/core';
import { tap } from 'rxjs';

import { environment } from '../../../environments/environment';
import { AuthService } from '../auth/auth';

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
  headline: string;
  overallAssessment: 'low' | 'medium' | 'high' | 'critical';
  summary: string;
  priorityFindings: DashboardFinding[];
  positiveObservations: string[];
  uncertainties: string[];
}

@Injectable({
  providedIn: 'root',
})
export class AIService {
  private readonly cachedDashboardSummary = signal<DashboardSummary | null>(null);
  private readonly cachedDashboardSummaryUserId = signal<string | null>(null);
  readonly dashboardSummary = computed(() => {
    const currentUserId = this.authService.session()?.user.id ?? null;

    if (currentUserId !== this.cachedDashboardSummaryUserId()) {
      return null;
    }

    return this.cachedDashboardSummary();
  });

  // Creates the service with the shared authenticated HTTP client.
  constructor(
    private readonly httpClient: HttpClient,
    private readonly authService: AuthService,
  ) {}

  // Requests a fresh, backend-grounded explanation for the current dashboard data.
  getDashboardSummary() {
    const requestingUserId = this.authService.session()?.user.id ?? null;

    return this.httpClient
      .post<DashboardSummary>(`${environment.apiUrl}/dashboard/ai-summary`, {})
      .pipe(
        tap((summary) => {
          if (!requestingUserId || this.authService.session()?.user.id !== requestingUserId) {
            return;
          }

          this.cachedDashboardSummaryUserId.set(requestingUserId);
          this.cachedDashboardSummary.set(summary);
        }),
      );
  }
}

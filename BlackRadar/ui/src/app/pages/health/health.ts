import { HttpClient } from '@angular/common/http';
import { DatePipe } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
import { finalize } from 'rxjs';
import { TopMenuComponent } from '../../components/top-menu/top-menu';
import { LoadingProgressComponent } from '../../components/loading-progress/loading-progress';
import { PageLayoutComponent } from '../../components/page-layout/page-layout';
import { environment } from '../../../environments/environment';
import { AuthService } from '../../services/auth/auth';

type HealthStatus = 'healthy' | 'unavailable' | 'not_configured';
type HealthSummary = {
  overall: HealthStatus;
  checkedAt: string;
  application: { status: HealthStatus };
  database: { status: HealthStatus };
  ai: { status: HealthStatus };
  nvd: { status: HealthStatus };
};

@Component({
  selector: 'app-health-page',
  standalone: true,
  imports: [DatePipe, LoadingProgressComponent, PageLayoutComponent, TopMenuComponent],
  templateUrl: './health.html',
  styleUrl: './health.css',
})
export class HealthPage {
  private readonly http = inject(HttpClient);
  private readonly auth = inject(AuthService);
  readonly session = this.auth.session;
  readonly summary = signal<HealthSummary | null>(null);
  readonly isLoading = signal(false);
  readonly hasError = signal(false);
  constructor() {
    this.refresh();
  }
  refresh(): void {
    this.isLoading.set(true);
    this.hasError.set(false);
    this.http
      .get<HealthSummary>(`${environment.apiUrl}/health/summary`)
      .pipe(finalize(() => this.isLoading.set(false)))
      .subscribe({
        next: (value) => this.summary.set(value),
        error: () => this.hasError.set(true),
      });
  }
  label(status: HealthStatus): string {
    return status === 'not_configured'
      ? 'Not configured'
      : status[0].toUpperCase() + status.slice(1);
  }
}

import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';

import { environment } from '../../../environments/environment';
import { AuthService } from '../../services/auth/auth';
import { HealthPage } from './health';

describe('HealthPage', () => {
  let fixture: ComponentFixture<HealthPage>;
  let httpTestingController: HttpTestingController;
  const authServiceMock = {
    session: () => null,
  };

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [HealthPage],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: AuthService, useValue: authServiceMock },
      ],
    }).compileComponents();

    httpTestingController = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(HealthPage);
  });

  afterEach(() => httpTestingController.verify());

  it('renders the NVD readiness card from the health summary', () => {
    fixture.detectChanges();
    httpTestingController.expectOne(`${environment.apiUrl}/health/summary`).flush({
      overall: 'healthy',
      checkedAt: '2026-08-23T12:00:00Z',
      application: { status: 'healthy' },
      database: { status: 'healthy' },
      ai: { status: 'healthy' },
      nvd: { status: 'healthy' },
    });
    fixture.detectChanges();

    const nvdCard = fixture.nativeElement.querySelector('.health-node--nvd') as HTMLElement;
    expect(nvdCard.textContent).toContain('NVD');
    expect(nvdCard.textContent).toContain('Healthy');
    expect(nvdCard.textContent).toContain('Vulnerability data');
    expect(nvdCard.closest('.health-node--app')).toBeNull();
    expect(fixture.nativeElement.querySelector('.health-app-link')).not.toBeNull();

    const databaseCard = fixture.nativeElement.querySelector(
      '.health-node--database',
    ) as HTMLElement;
    expect(databaseCard.textContent).toContain('PostgreSQL');
    expect(databaseCard.textContent).toContain('Healthy');
    expect(databaseCard.querySelector('.health-dependency-indicator')).not.toBeNull();
  });

  it('clears loading when the health request fails', () => {
    fixture.detectChanges();
    httpTestingController
      .expectOne(`${environment.apiUrl}/health/summary`)
      .flush({ error: 'Unavailable' }, { status: 503, statusText: 'Service Unavailable' });

    expect(fixture.componentInstance.isLoading()).toBe(false);
    expect(fixture.componentInstance.hasError()).toBe(true);
  });

  it('allows a failed health request to be retried', () => {
    fixture.detectChanges();
    httpTestingController
      .expectOne(`${environment.apiUrl}/health/summary`)
      .flush({ error: 'Unavailable' }, { status: 503, statusText: 'Service Unavailable' });
    fixture.detectChanges();

    const retryButton = fixture.nativeElement.querySelector(
      '.health-error-action',
    ) as HTMLButtonElement;
    expect(retryButton.disabled).toBe(false);

    retryButton.click();
    fixture.detectChanges();
    expect(fixture.componentInstance.isLoading()).toBe(true);
    expect(fixture.nativeElement.textContent).toContain('Loading system health');

    httpTestingController.expectOne(`${environment.apiUrl}/health/summary`).flush({
      overall: 'healthy',
      checkedAt: '2026-08-23T12:00:00Z',
      application: { status: 'healthy' },
      database: { status: 'healthy' },
      ai: { status: 'healthy' },
      nvd: { status: 'healthy' },
    });
    fixture.detectChanges();

    expect(fixture.componentInstance.hasError()).toBe(false);
    expect(fixture.nativeElement.querySelector('.health-system-card')).not.toBeNull();
  });
});

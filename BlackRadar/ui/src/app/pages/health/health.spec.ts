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
    expect(databaseCard.textContent).not.toContain('Healthy');
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
});

import { ComponentFixture, TestBed } from '@angular/core/testing';
import { signal } from '@angular/core';
import { Router } from '@angular/router';
import { of } from 'rxjs';

import { DashboardPage } from './dashboard';
import { AuthService, LoginResponse } from '../../services/auth/auth';
import { AssetsService } from '../../services/assets/assets';
import { BannerService } from '../../services/banner/banner';
import { VulnerabilitiesService } from '../../services/vulnerabilities/vulnerabilities';

describe('DashboardPage', () => {
  let fixture: ComponentFixture<DashboardPage>;

  const session: LoginResponse = {
    user: {
      id: 'user-1',
      fullName: 'System Admin',
      username: 'system_admin',
      email: 'system_admin@example.invalid',
    },
    token: 'token',
    tokenExpiresAt: '2026-08-11T12:00:00Z',
    refreshTokenExpiresAt: '2026-08-12T12:00:00Z',
  };

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [DashboardPage],
      providers: [
        {
          provide: AuthService,
          useValue: {
            session: signal(session),
            getSession: vi.fn(() => session),
            logout: vi.fn(),
          },
        },
        {
          provide: AssetsService,
          useValue: {
            getAssets: vi.fn(() =>
              of([
                { id: 'asset-1', vulnerabilityCount: 2, riskLevel: 'High', hasCveScan: true },
                { id: 'asset-2', vulnerabilityCount: 0, riskLevel: 'Low', hasCveScan: false },
              ]),
            ),
          },
        },
        {
          provide: VulnerabilitiesService,
          useValue: {
            getVulnerabilities: vi.fn(() =>
              of([
                { id: 'vulnerability-1', severity: 'Critical', affectedAssetCount: 1 },
                { id: 'vulnerability-2', severity: 'Medium', affectedAssetCount: 0 },
              ]),
            ),
          },
        },
        { provide: BannerService, useValue: { show: vi.fn() } },
        { provide: Router, useValue: { navigateByUrl: vi.fn(() => Promise.resolve(true)) } },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(DashboardPage);
    fixture.detectChanges();
  });

  it('renders the dashboard overview from the current assets and vulnerabilities', () => {
    const content = fixture.nativeElement as HTMLElement;

    expect(content.textContent).toContain('Assets');
    expect(content.textContent).toContain('1 unscanned asset');
    expect(content.textContent).toContain('Attached vulnerabilities');
    expect(content.textContent).toContain('Assigned assets');
    expect(content.textContent).toContain('Unaffected assets');
    expect(content.textContent).toContain('Unassigned vulnerabilities');
    expect(content.textContent).toContain('Asset risk chart');
    expect(content.textContent).toContain('Vulnerability severity chart');
    expect(content.querySelectorAll('.dashboard-overview-chart')).toHaveLength(2);
    expect(content.querySelectorAll('.dashboard-overview-coverage-bar')).toHaveLength(2);
    expect(content.querySelectorAll('.dashboard-overview-chart-percentage')).toHaveLength(8);
    expect(content.textContent).toContain('50%');
    expect(content.textContent).toContain('Medium');
    expect(content.textContent).toContain('2');
    expect(content.textContent).toContain('1');
  });

  it('uses the shared severity colors for pie-chart segments', () => {
    const component = fixture.componentInstance;

    expect(component.pieChartBackground({ critical: 1, high: 1, medium: 1, low: 1 })).toBe(
      'conic-gradient(var(--BlackRadar-color-severe) 0deg 90deg, var(--BlackRadar-color-error) 90deg 180deg, var(--BlackRadar-color-warning) 180deg 270deg, var(--BlackRadar-color-success) 270deg 360deg)',
    );
  });

  it('renders a navy-to-blue coverage bar from the current assignment count', () => {
    const component = fixture.componentInstance;

    expect(component.coverageBarBackground(1, 2)).toBe(
      'linear-gradient(to right, var(--BlackRadar-color-navy-black) 0% 50%, var(--brandRadar-color-blue) 50% 100%)',
    );
  });
});

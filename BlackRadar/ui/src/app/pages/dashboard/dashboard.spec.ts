import { ComponentFixture, TestBed } from '@angular/core/testing';
import { signal } from '@angular/core';
import { provideRouter } from '@angular/router';
import { of, tap, throwError } from 'rxjs';

import { DashboardPage } from './dashboard';
import { AuthService, LoginResponse } from '../../services/auth/auth';
import { AssetsService } from '../../services/assets/assets';
import { BannerService } from '../../services/banner/banner';
import { VulnerabilitiesService } from '../../services/vulnerabilities/vulnerabilities';
import { AIService, DashboardSummary } from '../../services/ai/ai';

describe('DashboardPage', () => {
  let fixture: ComponentFixture<DashboardPage>;
  let getDashboardSummary: ReturnType<typeof vi.fn>;
  let dashboardSummary: ReturnType<typeof signal<DashboardSummary | null>>;

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
    getDashboardSummary = vi.fn(() => of(null));
    dashboardSummary = signal<DashboardSummary | null>(null);
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
            getAssetSummary: vi.fn(() =>
              of({
                totalCount: 2,
                unscannedCount: 1,
                withVulnerabilitiesCount: 1,
                lowRiskCount: 1,
                mediumRiskCount: 0,
                highRiskCount: 1,
                criticalRiskCount: 0,
              }),
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
        { provide: AIService, useValue: { dashboardSummary, getDashboardSummary } },
        { provide: BannerService, useValue: { show: vi.fn() } },
        provideRouter([]),
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

  it('counts only assigned vulnerabilities in the severity chart', () => {
    expect(fixture.componentInstance.overview()?.vulnerabilitySeverityLevels).toEqual({
      critical: 1,
      high: 0,
      medium: 0,
      low: 0,
    });
  });

  it('renders a navy-to-blue coverage bar from the current assignment count', () => {
    const component = fixture.componentInstance;

    expect(component.coverageBarBackground(1, 2)).toBe(
      'linear-gradient(to right, var(--BlackRadar-color-navy-black) 0% 50%, var(--brandRadar-color-blue) 50% 100%)',
    );
  });

  it('requests and renders the optional AI dashboard summary on demand', () => {
    getDashboardSummary.mockReturnValue(
      of<DashboardSummary>({
        headline: 'One database needs immediate attention',
        overallAssessment: 'high',
        summary: 'A high-severity vulnerability affects an important asset.',
        priorityFindings: [
          {
            priority: 1,
            assetId: 'asset-1',
            assetName: 'DynamoDB',
            vulnerabilityId: 'vulnerability-1',
            cveId: 'CVE-2025-0001',
            explanation: 'The database is affected by a known injection flaw.',
            riskReason: 'An attacker could alter or read protected data.',
            recommendedNextStep: 'Review the affected version and apply the vendor fix.',
          },
        ],
        positiveObservations: ['One asset has no attached vulnerabilities.'],
        uncertainties: ['The affected version should be verified.'],
      }).pipe(tap((summary) => dashboardSummary.set(summary))),
    );

    const button = fixture.nativeElement.querySelector('.dashboard-ai-action') as HTMLButtonElement;
    button.click();
    fixture.detectChanges();

    expect(getDashboardSummary).toHaveBeenCalledOnce();
    expect(fixture.nativeElement.textContent).toContain('One database needs immediate attention');
    expect(fixture.nativeElement.textContent).toContain('DynamoDB');
    expect(fixture.nativeElement.textContent).toContain('What is going well');
    expect(fixture.nativeElement.querySelector('a[href="/assets/asset-1"]')).not.toBeNull();

    const toggleButton = fixture.nativeElement.querySelector(
      '.dashboard-ai-toggle',
    ) as HTMLButtonElement;
    toggleButton.click();
    fixture.detectChanges();

    expect(fixture.nativeElement.querySelector('.dashboard-ai-card--expanded')).toBeNull();
    expect(fixture.nativeElement.textContent).toContain('Refresh summary');
  });

  it('keeps the generate action when an empty card is expanded', () => {
    const toggleButton = fixture.nativeElement.querySelector(
      '.dashboard-ai-toggle',
    ) as HTMLButtonElement;
    toggleButton.click();
    fixture.detectChanges();

    const actionButton = fixture.nativeElement.querySelector(
      '.dashboard-ai-action',
    ) as HTMLButtonElement;
    expect(actionButton.textContent).toContain('Generate AI Risk Summary');
    expect(actionButton.textContent).not.toContain('Refresh summary');
  });

  it('keeps the generated summary when the dashboard component is recreated', () => {
    const summary: DashboardSummary = {
      headline: 'Cached summary',
      overallAssessment: 'low',
      summary: 'The current findings are under control.',
      priorityFindings: [],
      positiveObservations: [],
      uncertainties: [],
    };
    dashboardSummary.set(summary);

    const secondFixture = TestBed.createComponent(DashboardPage);
    secondFixture.detectChanges();

    expect(secondFixture.componentInstance.aiSummary()).toEqual(summary);
    expect(secondFixture.nativeElement.textContent).toContain('Cached summary');
    secondFixture.destroy();
  });

  it('clears the AI loading state when the summary request fails', () => {
    getDashboardSummary.mockReturnValue(throwError(() => new Error('provider unavailable')));
    const component = fixture.componentInstance;

    component.generateAISummary();

    expect(component.isAISummaryLoading()).toBe(false);
    expect(component.hasAISummaryError()).toBe(true);
  });

  it('keeps the AI action available when the overview request fails', async () => {
    await TestBed.resetTestingModule()
      .configureTestingModule({
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
              getAssetSummary: vi.fn(() => throwError(() => new Error('overview unavailable'))),
            },
          },
          {
            provide: VulnerabilitiesService,
            useValue: {
              getVulnerabilities: vi.fn(() =>
                of([{ id: 'vulnerability-1', severity: 'Critical', affectedAssetCount: 1 }]),
              ),
            },
          },
          { provide: AIService, useValue: { dashboardSummary, getDashboardSummary } },
          { provide: BannerService, useValue: { show: vi.fn() } },
          provideRouter([]),
        ],
      })
      .compileComponents();

    const overviewFailureFixture = TestBed.createComponent(DashboardPage);
    overviewFailureFixture.detectChanges();

    expect(overviewFailureFixture.nativeElement.textContent).toContain(
      'Unable to load dashboard metrics',
    );
    expect(
      overviewFailureFixture.nativeElement.querySelector('.dashboard-ai-action'),
    ).not.toBeNull();
    overviewFailureFixture.destroy();
  });
});

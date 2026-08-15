import { Location } from '@angular/common';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { signal } from '@angular/core';
import { ActivatedRoute, convertToParamMap, provideRouter, Router } from '@angular/router';
import { of } from 'rxjs';

import { AssetVulnerabilitiesPage } from './asset-vulnerabilities';
import { AuthService, LoginResponse } from '../../services/auth/auth';
import { Asset, AssetVulnerabilitiesResponse, AssetsService } from '../../services/assets/assets';
import { Vulnerability } from '../../services/vulnerabilities/vulnerabilities';

describe('AssetVulnerabilitiesPage', () => {
  let fixture: ComponentFixture<AssetVulnerabilitiesPage>;
  let component: AssetVulnerabilitiesPage;
  let assetsServiceMock: { getAssetVulnerabilities: ReturnType<typeof vi.fn> };
  let router: Router;
  let location: { back: ReturnType<typeof vi.fn> };

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
  const vulnerability: Vulnerability = {
    id: 'vulnerability-1',
    source: 'CVE',
    cveId: 'CVE-2026-1234',
    title: 'Example vulnerability',
    severity: 'High',
    description: 'Example description',
    status: 'Open',
    affectedAssetCount: 1,
    createdAt: '2026-08-11T12:00:00Z',
    updatedAt: '2026-08-11T12:00:00Z',
  };
  const response: AssetVulnerabilitiesResponse = {
    id: 'asset-1',
    name: 'Alpha server',
    type: 'Server',
    operatingSystem: 'Linux',
    vendor: 'Dell',
    product: 'PowerEdge',
    version: '1.0',
    owner: 'Platform',
    criticality: 'High',
    riskLevel: 'Medium',
    vulnerabilityCount: 1,
    createdAt: '2026-08-11T12:00:00Z',
    updatedAt: '2026-08-11T12:00:00Z',
    vulnerabilities: [vulnerability],
  };

  beforeEach(async () => {
    assetsServiceMock = {
      getAssetVulnerabilities: vi.fn(() => of(response)),
    };
    location = { back: vi.fn() };

    await TestBed.configureTestingModule({
      imports: [AssetVulnerabilitiesPage],
      providers: [
        provideRouter([]),
        {
          provide: ActivatedRoute,
          useValue: { paramMap: of(convertToParamMap({ id: 'asset-1' })) },
        },
        { provide: AuthService, useValue: { session: signal(session) } },
        { provide: AssetsService, useValue: assetsServiceMock },
        { provide: Location, useValue: location },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(AssetVulnerabilitiesPage);
    component = fixture.componentInstance;
    router = TestBed.inject(Router);
    vi.spyOn(router, 'navigate').mockResolvedValue(true);
    fixture.detectChanges();
  });

  it('loads attached vulnerabilities and uses the vulnerability id as the row key', () => {
    expect(assetsServiceMock.getAssetVulnerabilities).toHaveBeenCalledWith('asset-1');
    expect(component.vulnerabilities()).toEqual([vulnerability]);
    expect(component.vulnerabilityRowKey(vulnerability)).toBe('vulnerability-1');
    expect(fixture.nativeElement.textContent).toContain('Attached Vulnerabilities');
  });

  it('navigates to affected assets when an affected-assets count is selected', async () => {
    await component.handleTableAction({
      column: component.vulnerabilityColumns.find((column) => column.key === 'affectedAssetCount')!,
      row: vulnerability,
    });

    expect(router.navigate).toHaveBeenCalledWith(['/vulnerabilities', 'vulnerability-1', 'assets']);
  });

  it('uses browser history for the back button', () => {
    component.goBack();

    expect(location.back).toHaveBeenCalledTimes(1);
  });
});

import { Location } from '@angular/common';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { signal } from '@angular/core';
import { ActivatedRoute, convertToParamMap, provideRouter, Router } from '@angular/router';
import { of, Subject } from 'rxjs';

import { AssetVulnerabilitiesPage } from './asset-vulnerabilities';
import { AuthService, LoginResponse } from '../../services/auth/auth';
import { BannerService } from '../../services/banner/banner';
import {
  Asset,
  AssetMatchPreviewResponse,
  AssetVulnerabilitiesResponse,
  AssetsService,
} from '../../services/assets/assets';
import {
  Vulnerability,
  VulnerabilitiesService,
} from '../../services/vulnerabilities/vulnerabilities';

describe('AssetVulnerabilitiesPage', () => {
  let fixture: ComponentFixture<AssetVulnerabilitiesPage>;
  let component: AssetVulnerabilitiesPage;
  let assetsServiceMock: {
    getAssetVulnerabilities: ReturnType<typeof vi.fn>;
    assignVulnerability: ReturnType<typeof vi.fn>;
    removeVulnerability: ReturnType<typeof vi.fn>;
    previewCVEScan: ReturnType<typeof vi.fn>;
    applyCVEScan: ReturnType<typeof vi.fn>;
  };
  let vulnerabilitiesServiceMock: { getVulnerabilities: ReturnType<typeof vi.fn> };
  let bannerServiceMock: { show: ReturnType<typeof vi.fn> };
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
    hasCveScan: true,
    vulnerabilityCount: 1,
    createdAt: '2026-08-11T12:00:00Z',
    updatedAt: '2026-08-11T12:00:00Z',
    vulnerabilities: [vulnerability],
  };
  const availableVulnerability: Vulnerability = {
    ...vulnerability,
    id: 'vulnerability-2',
    cveId: 'CVE-2026-5678',
    title: 'Unattached vulnerability',
    affectedAssetCount: 0,
  };

  beforeEach(async () => {
    assetsServiceMock = {
      getAssetVulnerabilities: vi.fn(() => of(response)),
      assignVulnerability: vi.fn(() => of({ ...response, vulnerabilityCount: 2 })),
      removeVulnerability: vi.fn(() => of({ ...response, vulnerabilityCount: 0 })),
      previewCVEScan: vi.fn(() =>
        of({
          productFingerprint: 'vendor=dell;product=poweredge;version=1.0',
          selectedCpe: 'cpe:2.3:h:dell:poweredge:1.0:*:*:*:*:*:*:*',
          cveCount: 1,
          cveIds: ['CVE-2026-5678'],
          cveDataAvailable: true,
          confidence: 0.96,
          reviewStatus: 'needs_review',
          candidateCount: 1,
          candidates: [
            {
              cpeName: 'cpe:2.3:h:dell:poweredge:1.0:*:*:*:*:*:*:*',
              title: 'Dell PowerEdge 1.0',
            },
            {
              cpeName: 'cpe:2.3:h:dell:poweredge:1.1:*:*:*:*:*:*:*',
              title: 'Dell PowerEdge 1.1',
            },
          ],
        }),
      ),
      applyCVEScan: vi.fn(() =>
        of({
          asset: {
            ...response,
            vulnerabilityCount: 2,
            vulnerabilities: [{ ...availableVulnerability, affectedAssetCount: 1 }],
          },
          assetAssessment: {},
        }),
      ),
    };
    vulnerabilitiesServiceMock = {
      getVulnerabilities: vi.fn(() => of([vulnerability, availableVulnerability])),
    };
    bannerServiceMock = { show: vi.fn() };
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
        { provide: BannerService, useValue: bannerServiceMock },
        { provide: VulnerabilitiesService, useValue: vulnerabilitiesServiceMock },
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
    const scanIconUse = fixture.nativeElement.querySelector(
      '.asset-vulnerabilities-scan-icon use',
    ) as SVGUseElement;
    expect(scanIconUse.getAttribute('href')).toBe('#asset-cve-ai-sparkle');
    const scanButton = fixture.nativeElement.querySelector(
      '.asset-vulnerabilities-scan-button',
    ) as HTMLButtonElement;
    expect(scanButton.getAttribute('aria-controls')).toBe('asset-vulnerabilities-scan-panel');
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

  it('shows only unattached vulnerabilities in the attach panel', () => {
    component.toggleAttachPanel();
    fixture.detectChanges();

    expect(component.availableVulnerabilities()).toEqual([availableVulnerability]);
    const availableList = fixture.nativeElement.querySelector(
      '.asset-vulnerabilities-available-list',
    ) as HTMLElement;
    expect(availableList.textContent).toContain('Unattached vulnerability');
    expect(availableList.textContent).not.toContain('Example vulnerability');
  });

  it('attaches the confirmed vulnerability', () => {
    component.requestAttachment(availableVulnerability);
    expect(component.pendingAttachment()).toEqual(availableVulnerability);

    component.confirmAttachment();

    expect(assetsServiceMock.assignVulnerability).toHaveBeenCalledWith(
      'asset-1',
      'vulnerability-2',
    );
    expect(component.vulnerabilities()).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: 'vulnerability-2', affectedAssetCount: 1 }),
      ]),
    );
    expect(
      component.allVulnerabilities().find((item) => item.id === 'vulnerability-2'),
    ).toMatchObject({ affectedAssetCount: 1 });
    expect(bannerServiceMock.show).toHaveBeenCalledWith(
      'Vulnerability attached successfully.',
      'success',
    );
  });

  it('detaches the confirmed vulnerability', () => {
    component.requestDetachment(vulnerability);
    expect(component.pendingDetachment()).toEqual(vulnerability);

    component.confirmDetachment();

    expect(assetsServiceMock.removeVulnerability).toHaveBeenCalledWith(
      'asset-1',
      'vulnerability-1',
    );
    expect(component.vulnerabilities()).not.toContain(vulnerability);
    expect(bannerServiceMock.show).toHaveBeenCalledWith(
      'Vulnerability detached successfully.',
      'success',
    );
  });

  it('previews and confirms a CVE scan from the manage box', () => {
    component.scanCVEs();
    fixture.detectChanges();

    expect(assetsServiceMock.previewCVEScan).toHaveBeenCalledWith('asset-1');
    expect(component.selectedScanCPE()).toBe('cpe:2.3:h:dell:poweredge:1.0:*:*:*:*:*:*:*');
    expect(fixture.nativeElement.querySelector('#asset-vulnerabilities-scan-panel')).not.toBeNull();
    expect(
      fixture.nativeElement.querySelector('.asset-vulnerabilities-scan-candidates').textContent,
    ).toContain('Dell PowerEdge 1.0');
    component.selectScanCPE('cpe:2.3:h:dell:poweredge:1.1:*:*:*:*:*:*:*');

    expect(assetsServiceMock.previewCVEScan).toHaveBeenCalledTimes(1);
    expect(component.selectedScanCPE()).toBe('cpe:2.3:h:dell:poweredge:1.1:*:*:*:*:*:*:*');

    component.requestScanApply();
    fixture.detectChanges();

    expect(component.scanApplyConfirmationMessage()).toBe(
      'Attach the matching CVE findings to Alpha server?',
    );
    vulnerabilitiesServiceMock.getVulnerabilities.mockReturnValueOnce(
      of([vulnerability, { ...availableVulnerability, affectedAssetCount: 1 }]),
    );
    component.confirmScanApply();

    expect(assetsServiceMock.applyCVEScan).toHaveBeenCalledWith(
      'asset-1',
      'cpe:2.3:h:dell:poweredge:1.1:*:*:*:*:*:*:*',
    );
    expect(bannerServiceMock.show).toHaveBeenCalledWith(
      'CVE findings attached successfully.',
      'success',
    );
    expect(
      component.allVulnerabilities().find((item) => item.id === 'vulnerability-2'),
    ).toMatchObject({ affectedAssetCount: 1 });
    expect(component.vulnerabilities()).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: 'vulnerability-2', affectedAssetCount: 1 }),
      ]),
    );
  });

  it('shows scan progress while the CVE scan is in flight', () => {
    const scanPreview = new Subject<AssetMatchPreviewResponse>();
    assetsServiceMock.previewCVEScan.mockReturnValueOnce(scanPreview);

    component.scanCVEs();
    fixture.detectChanges();

    const progress = fixture.nativeElement.querySelector(
      'app-loading-progress .loading-progress',
    ) as HTMLElement;
    expect(progress.getAttribute('role')).toBe('progressbar');
    expect(progress.getAttribute('aria-valuetext')).toBe('Scanning NVD for matching CVEs');
    expect(progress.querySelector('.loading-progress-indicator')).not.toBeNull();
    scanPreview.error(new Error('Request failed'));
  });

  it('hides only the panel button that was selected', () => {
    component.scanCVEs();
    fixture.detectChanges();

    expect(fixture.nativeElement.querySelector('.asset-vulnerabilities-scan-button')).toBeNull();
    expect(
      fixture.nativeElement.querySelector('.asset-vulnerabilities-attach-button'),
    ).not.toBeNull();

    component.cancelScan();
    component.toggleAttachPanel();
    fixture.detectChanges();

    expect(
      fixture.nativeElement.querySelector('.asset-vulnerabilities-scan-button'),
    ).not.toBeNull();
    expect(fixture.nativeElement.querySelector('.asset-vulnerabilities-attach-button')).toBeNull();
  });
});

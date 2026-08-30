import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';

import { environment } from '../../../environments/environment';
import { AssetsService } from './assets';

describe('AssetsService', () => {
  let service: AssetsService;
  let httpTestingController: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(AssetsService);
    httpTestingController = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpTestingController.verify();
  });

  it('requests vulnerabilities attached to an asset', () => {
    service.getAssetVulnerabilities('asset-1').subscribe();

    const request = httpTestingController.expectOne(
      `${environment.apiUrl}/assets/asset-1/vulnerabilities`,
    );
    expect(request.request.method).toBe('GET');
    request.flush({});
  });

  it('requests one asset inventory page', () => {
    service
      .getAssetPage({
        page: 2,
        search: 'server',
        criticality: 'High',
        vulnerabilityMode: 'atLeast',
        vulnerabilityValue: 2,
        sortField: 'vulnerabilityCount',
        sortDirection: 'desc',
      })
      .subscribe();

    const request = httpTestingController.expectOne(
      `${environment.apiUrl}/assets?page=2&search=server&criticality=High&vulnerabilityMode=atLeast&sortField=vulnerabilityCount&sortDirection=desc&vulnerabilityValue=2`,
    );
    expect(request.request.method).toBe('GET');
    request.flush({
      assets: [],
      pagination: { page: 2, pageSize: 6, totalCount: 10, totalPages: 2 },
    });
  });

  it('requests the Asset dashboard summary', () => {
    service.getAssetSummary().subscribe();

    const request = httpTestingController.expectOne(`${environment.apiUrl}/assets/summary`);
    expect(request.request.method).toBe('GET');
    request.flush({
      totalCount: 2,
      unscannedCount: 1,
      withVulnerabilitiesCount: 1,
      lowRiskCount: 1,
      mediumRiskCount: 0,
      highRiskCount: 1,
      criticalRiskCount: 0,
    });
  });

  it('assigns an existing vulnerability to an asset', () => {
    service.assignVulnerability('asset-1', 'vulnerability-1').subscribe();

    const request = httpTestingController.expectOne(
      `${environment.apiUrl}/assets/asset-1/vulnerabilities/vulnerability-1`,
    );
    expect(request.request.method).toBe('POST');
    expect(request.request.body).toEqual({});
    request.flush({});
  });

  it('removes a vulnerability from an asset', () => {
    service.removeVulnerability('asset-1', 'vulnerability-1').subscribe();

    const request = httpTestingController.expectOne(
      `${environment.apiUrl}/assets/asset-1/vulnerabilities/vulnerability-1`,
    );
    expect(request.request.method).toBe('DELETE');
    request.flush({});
  });

  it('previews a CVE scan for one asset', () => {
    service.previewCVEScan('asset-1').subscribe();

    const request = httpTestingController.expectOne(
      `${environment.apiUrl}/assets/asset-1/match-cpe/preview`,
    );
    expect(request.request.method).toBe('POST');
    expect(request.request.body).toEqual({});
    request.flush({});
  });

  it('applies an approved CPE CVE scan for one asset', () => {
    service.applyCVEScan('asset-1', 'cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*').subscribe();

    const request = httpTestingController.expectOne(
      `${environment.apiUrl}/assets/asset-1/match-cpe/vulnerabilities/apply`,
    );
    expect(request.request.method).toBe('POST');
    expect(request.request.body).toEqual({
      selectedCpe: 'cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*',
    });
    request.flush({});
  });
});

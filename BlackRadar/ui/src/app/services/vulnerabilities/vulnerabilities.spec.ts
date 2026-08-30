import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';

import { environment } from '../../../environments/environment';
import { VulnerabilitiesService } from './vulnerabilities';

describe('VulnerabilitiesService', () => {
  let service: VulnerabilitiesService;
  let httpTestingController: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(VulnerabilitiesService);
    httpTestingController = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpTestingController.verify();
  });

  it('requests assets affected by a vulnerability', () => {
    service.getVulnerabilityAssets('vulnerability-1').subscribe();

    const request = httpTestingController.expectOne(
      `${environment.apiUrl}/vulnerabilities/vulnerability-1/assets`,
    );
    expect(request.request.method).toBe('GET');
    request.flush({});
  });

  it('requests assets available to a vulnerability', () => {
    service.getAvailableAssets('vulnerability-1').subscribe();

    const request = httpTestingController.expectOne(
      `${environment.apiUrl}/vulnerabilities/vulnerability-1/available-assets`,
    );
    expect(request.request.method).toBe('GET');
    request.flush([]);
  });
});

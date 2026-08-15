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
});

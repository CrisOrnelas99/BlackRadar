// Loads the authenticated user's vulnerabilities from the backend vulnerability endpoint.
import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';

import { environment } from '../../../environments/environment';

export interface Vulnerability {
  id: string;
  source: 'CVE' | 'Manual';
  cveId: string;
  title: string;
  severity: string;
  description: string;
  status: string;
  nvdPublishedAt?: string;
  affectedAssetCount: number;
  createdAt: string;
  updatedAt: string;
}

export interface AffectedAsset {
  id: string;
  name: string;
  type: string;
  criticality: string;
  riskLevel: string | null;
  vulnerabilityCount: number;
}

export interface VulnerabilityAssetsResponse extends Vulnerability {
  assets: AffectedAsset[];
}

export interface CreateVulnerabilityRequest {
  cveId: string;
  title: string;
  severity: string;
  description: string;
  status: string;
}

export type UpdateVulnerabilityRequest = CreateVulnerabilityRequest;

@Injectable({
  providedIn: 'root',
})
export class VulnerabilitiesService {
  constructor(private readonly httpClient: HttpClient) {}

  getVulnerabilities() {
    return this.httpClient.get<Vulnerability[]>(`${environment.apiUrl}/vulnerabilities`);
  }

  createVulnerability(request: CreateVulnerabilityRequest) {
    return this.httpClient.post<Vulnerability>(`${environment.apiUrl}/vulnerabilities`, request);
  }

  getVulnerability(vulnerabilityID: string) {
    return this.httpClient.get<Vulnerability>(
      `${environment.apiUrl}/vulnerabilities/${vulnerabilityID}`,
    );
  }

  getVulnerabilityAssets(vulnerabilityID: string) {
    return this.httpClient.get<VulnerabilityAssetsResponse>(
      `${environment.apiUrl}/vulnerabilities/${vulnerabilityID}/assets`,
    );
  }

  getAvailableAssets(vulnerabilityID: string) {
    return this.httpClient.get<AffectedAsset[]>(
      `${environment.apiUrl}/vulnerabilities/${vulnerabilityID}/available-assets`,
    );
  }

  updateVulnerability(vulnerabilityID: string, request: UpdateVulnerabilityRequest) {
    return this.httpClient.put<Vulnerability>(
      `${environment.apiUrl}/vulnerabilities/${vulnerabilityID}`,
      request,
    );
  }

  deleteVulnerability(vulnerabilityID: string) {
    return this.httpClient.delete<void>(`${environment.apiUrl}/vulnerabilities/${vulnerabilityID}`);
  }
}

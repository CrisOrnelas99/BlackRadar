// Loads the authenticated user's assets from the backend asset endpoint.
import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';

import { environment } from '../../../environments/environment';
import { Vulnerability } from '../vulnerabilities/vulnerabilities';

export interface Asset {
  id: string;
  name: string;
  type: string;
  description?: string;
  operatingSystem: string | null;
  vendor?: string;
  product?: string;
  version?: string;
  owner: string;
  criticality: string;
  riskLevel: string | null;
  vulnerabilityCount: number;
  createdAt: string;
  updatedAt: string;
}

export interface AssetVulnerabilitiesResponse extends Asset {
  vulnerabilities?: Vulnerability[];
}

export interface AssetMatchPreviewResponse {
  productFingerprint: string;
  selectedCpe?: string;
  cveCount: number;
  cveIds: string[];
  cveDataAvailable: boolean;
  confidence?: number;
  reviewStatus: string;
  reviewNotes?: string;
  candidateCount: number;
  candidates: Array<{ cpeName: string; title: string }>;
}

export interface AssetMatchResponse {
  asset: AssetVulnerabilitiesResponse;
  assetAssessment: Record<string, unknown>;
}

export interface ManualAssetRequest {
  name: string;
  type: string;
  description?: string;
  operatingSystem?: string;
  vendor: string;
  product: string;
  version: string;
  owner?: string;
  criticality: string;
}

export type CreateAssetRequest = ManualAssetRequest;

@Injectable({
  providedIn: 'root',
})
export class AssetsService {
  // Creates the service with the shared HTTP client.
  constructor(private readonly httpClient: HttpClient) {}

  // Returns all assets visible to the authenticated user.
  getAssets() {
    return this.httpClient.get<Asset[]>(`${environment.apiUrl}/assets`);
  }

  // Returns one asset visible to the authenticated user.
  getAsset(assetID: string) {
    return this.httpClient.get<Asset>(`${environment.apiUrl}/assets/${assetID}`);
  }

  getAssetVulnerabilities(assetID: string) {
    return this.httpClient.get<AssetVulnerabilitiesResponse>(
      `${environment.apiUrl}/assets/${assetID}/vulnerabilities`,
    );
  }

  assignVulnerability(assetID: string, vulnerabilityID: string) {
    return this.httpClient.post<Asset>(
      `${environment.apiUrl}/assets/${assetID}/vulnerabilities/${vulnerabilityID}`,
      {},
    );
  }

  removeVulnerability(assetID: string, vulnerabilityID: string) {
    return this.httpClient.delete<Asset>(
      `${environment.apiUrl}/assets/${assetID}/vulnerabilities/${vulnerabilityID}`,
    );
  }

  previewCVEScan(assetID: string, selectedCPE?: string) {
    return this.httpClient.post<AssetMatchPreviewResponse>(
      `${environment.apiUrl}/assets/${assetID}/match-cpe/preview`,
      selectedCPE ? { selectedCpe: selectedCPE } : {},
    );
  }

  applyCVEScan(assetID: string, selectedCPE: string) {
    return this.httpClient.post<AssetMatchResponse>(
      `${environment.apiUrl}/assets/${assetID}/match-cpe/vulnerabilities/apply`,
      { selectedCpe: selectedCPE },
    );
  }

  // Creates a manually entered asset for the authenticated user.
  createAsset(request: CreateAssetRequest) {
    return this.httpClient.post<Asset>(`${environment.apiUrl}/assets`, request);
  }

  // Updates an asset owned by the authenticated user.
  updateAsset(assetID: string, request: ManualAssetRequest) {
    return this.httpClient.put<Asset>(`${environment.apiUrl}/assets/${assetID}`, request);
  }

  // Deletes an asset owned by the authenticated user.
  deleteAsset(assetID: string) {
    return this.httpClient.delete<void>(`${environment.apiUrl}/assets/${assetID}`);
  }
}

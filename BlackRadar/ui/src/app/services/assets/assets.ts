// Loads the authenticated user's assets from the backend asset endpoint.
import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';

import { environment } from '../../../environments/environment';

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

export interface ManualAssetRequest {
  name: string;
  type: string;
  description?: string;
  operatingSystem?: string;
  vendor?: string;
  product?: string;
  version?: string;
  owner: string;
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

// Loads the authenticated user's assets from the backend asset endpoint.
import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';

import { environment } from '../../../environments/environment';

export interface Asset {
  id: string;
  name: string;
  type: string;
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
}

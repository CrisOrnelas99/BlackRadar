// Asset model used to describe frontend asset data shapes.
export interface Asset {
  id: number;
  name: string;
  type: string;
  ipAddress: string;
  operatingSystem: string;
  owner: string;
  criticality: string;
  riskScore: number;
  riskLevel: string;
  createdAt: string;
  updatedAt: string;
}

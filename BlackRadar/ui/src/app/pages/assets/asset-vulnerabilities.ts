// Authenticated page that lists vulnerabilities attached to one asset.
import { CommonModule, Location } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { EMPTY, map, switchMap } from 'rxjs';

import {
  DataTableCellAction,
  DataTableColumn,
  DataTableComponent,
} from '../../components/data-table/data-table';
import { TopMenuComponent } from '../../components/top-menu/top-menu';
import { AuthService } from '../../services/auth/auth';
import { Asset, AssetVulnerabilitiesResponse, AssetsService } from '../../services/assets/assets';
import { Vulnerability } from '../../services/vulnerabilities/vulnerabilities';
import { semanticLevelClass } from '../../utils/semantic-level';

@Component({
  selector: 'app-asset-vulnerabilities-page',
  standalone: true,
  imports: [CommonModule, DataTableComponent, TopMenuComponent],
  templateUrl: './asset-vulnerabilities.html',
  styleUrl: './asset-vulnerabilities.css',
})
export class AssetVulnerabilitiesPage {
  private readonly activatedRoute = inject(ActivatedRoute);
  private readonly assetsService = inject(AssetsService);
  private readonly authService = inject(AuthService);
  private readonly location = inject(Location);
  private readonly router = inject(Router);

  readonly session = this.authService.session;
  readonly asset = signal<Asset | null>(null);
  readonly vulnerabilities = signal<Vulnerability[]>([]);
  readonly isLoading = signal(true);
  readonly hasLoadError = signal(false);
  readonly vulnerabilityColumns: readonly DataTableColumn<Vulnerability>[] = [
    {
      key: 'status',
      label: 'Status',
      cellValue: (vulnerability) => vulnerability.status,
    },
    {
      key: 'title',
      label: 'Title',
      cellValue: (vulnerability) => vulnerability.title,
      cellType: 'link',
      cellLink: (vulnerability) => ['/vulnerabilities', vulnerability.id],
      width: '55%',
    },
    {
      key: 'severity',
      label: 'Severity',
      cellValue: (vulnerability) => vulnerability.severity,
      cellClass: (vulnerability) => semanticLevelClass(vulnerability.severity),
    },
    {
      key: 'cveId',
      label: 'CVE ID',
      cellValue: (vulnerability) => vulnerability.cveId || 'Custom finding',
    },
    {
      key: 'affectedAssetCount',
      label: 'Affected assets',
      cellValue: (vulnerability) => String(vulnerability.affectedAssetCount),
      cellType: 'action',
    },
  ];
  readonly vulnerabilityRowKey = (vulnerability: Vulnerability): string => vulnerability.id;

  constructor() {
    this.activatedRoute.paramMap
      .pipe(
        map((paramMap) => paramMap.get('id')),
        switchMap((assetID) => {
          this.isLoading.set(true);
          this.hasLoadError.set(false);

          if (!assetID) {
            this.hasLoadError.set(true);
            this.isLoading.set(false);
            return EMPTY;
          }

          return this.assetsService.getAssetVulnerabilities(assetID);
        }),
      )
      .subscribe({
        next: (response: AssetVulnerabilitiesResponse) => {
          this.asset.set(response);
          this.vulnerabilities.set(response.vulnerabilities);
          this.isLoading.set(false);
        },
        error: () => {
          this.hasLoadError.set(true);
          this.isLoading.set(false);
        },
      });
  }

  async handleTableAction(action: DataTableCellAction<Vulnerability>): Promise<void> {
    if (action.column.key === 'affectedAssetCount') {
      await this.router.navigate(['/vulnerabilities', action.row.id, 'assets']);
    }
  }

  goBack(): void {
    this.location.back();
  }
}

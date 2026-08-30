// Authenticated page that lists vulnerabilities attached to one asset.
import { CommonModule, Location } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { EMPTY, catchError, map, of, switchMap, tap } from 'rxjs';

import { ConfirmationDialogComponent } from '../../components/confirmation-dialog/confirmation-dialog';
import {
  DataTableCellAction,
  DataTableColumn,
  DataTableComponent,
} from '../../components/data-table/data-table';
import { TopMenuComponent } from '../../components/top-menu/top-menu';
import { PaginationComponent } from '../../components/pagination/pagination';
import { LoadingProgressComponent } from '../../components/loading-progress/loading-progress';
import { AuthService } from '../../services/auth/auth';
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
import { semanticLevelClass } from '../../utils/semantic-level';

@Component({
  selector: 'app-asset-vulnerabilities-page',
  standalone: true,
  imports: [
    CommonModule,
    ConfirmationDialogComponent,
    DataTableComponent,
    LoadingProgressComponent,
    PaginationComponent,
    RouterLink,
    TopMenuComponent,
  ],
  templateUrl: './asset-vulnerabilities.html',
  styleUrl: './asset-vulnerabilities.css',
})
export class AssetVulnerabilitiesPage {
  private readonly activatedRoute = inject(ActivatedRoute);
  private readonly assetsService = inject(AssetsService);
  private readonly authService = inject(AuthService);
  private readonly bannerService = inject(BannerService);
  private readonly location = inject(Location);
  private readonly router = inject(Router);
  private readonly vulnerabilitiesService = inject(VulnerabilitiesService);

  readonly session = this.authService.session;
  readonly asset = signal<Asset | null>(null);
  readonly vulnerabilities = signal<Vulnerability[]>([]);
  readonly allVulnerabilities = signal<Vulnerability[]>([]);
  readonly isAttachPanelOpen = signal(false);
  readonly pendingAttachment = signal<Vulnerability | null>(null);
  readonly isAttaching = signal(false);
  readonly pendingDetachment = signal<Vulnerability | null>(null);
  readonly isDetaching = signal(false);
  readonly isScanPanelOpen = signal(false);
  readonly isScanning = signal(false);
  readonly isApplyingScan = signal(false);
  readonly scanResult = signal<AssetMatchPreviewResponse | null>(null);
  readonly selectedScanCPE = signal<string | null>(null);
  readonly pendingScanCPE = signal<string | null>(null);
  readonly isLoading = signal(true);
  readonly hasLoadError = signal(false);
  readonly scanApplyConfirmationMessage = computed(() => {
    const assetName = this.asset()?.name || 'this asset';
    return `Attach the matching CVE findings to ${assetName}?`;
  });
  readonly availableVulnerabilities = computed(() => {
    const attachedIDs = new Set(this.vulnerabilities().map((vulnerability) => vulnerability.id));
    return this.allVulnerabilities().filter((vulnerability) => !attachedIDs.has(vulnerability.id));
  });
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
      cellValue: (vulnerability) => vulnerability.cveId || '—',
    },
    {
      key: 'affectedAssetCount',
      label: 'Affected assets',
      cellValue: (vulnerability) => String(vulnerability.affectedAssetCount),
      cellType: 'action',
    },
    {
      key: 'detach',
      label: 'Detach',
      cellValue: () => '',
      cellType: 'unlink',
      deleteLabel: 'Detach vulnerability',
      width: '3.5rem',
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

          return this.assetsService.getAssetVulnerabilities(assetID).pipe(
            tap((response: AssetVulnerabilitiesResponse) => {
              this.asset.set(response);
              this.vulnerabilities.set(response.vulnerabilities ?? []);
              this.isLoading.set(false);
            }),
            switchMap(() =>
              this.vulnerabilitiesService.getVulnerabilities().pipe(catchError(() => of([]))),
            ),
          );
        }),
      )
      .subscribe({
        next: (vulnerabilities: Vulnerability[]) => this.allVulnerabilities.set(vulnerabilities),
        error: () => {
          this.hasLoadError.set(true);
          this.isLoading.set(false);
        },
      });
  }

  async handleTableAction(action: DataTableCellAction<Vulnerability>): Promise<void> {
    if (action.column.key === 'affectedAssetCount') {
      await this.router.navigate(['/vulnerabilities', action.row.id, 'assets']);
      return;
    }

    if (action.column.key === 'detach') {
      this.requestDetachment(action.row);
    }
  }

  toggleAttachPanel(): void {
    if (
      !this.isAttaching() &&
      !this.isDetaching() &&
      !this.isScanning() &&
      !this.isApplyingScan()
    ) {
      this.isScanPanelOpen.set(false);
      this.scanResult.set(null);
      this.selectedScanCPE.set(null);
      this.pendingScanCPE.set(null);
      this.isAttachPanelOpen.update((isOpen) => !isOpen);
    }
  }

  scanCVEs(): void {
    const asset = this.asset();
    if (
      asset === null ||
      this.isScanning() ||
      this.isApplyingScan() ||
      this.isAttaching() ||
      this.isDetaching()
    ) {
      return;
    }

    this.isAttachPanelOpen.set(false);
    this.isScanPanelOpen.set(true);
    this.scanResult.set(null);
    this.selectedScanCPE.set(null);
    this.pendingScanCPE.set(null);
    this.isScanning.set(true);
    this.assetsService.previewCVEScan(asset.id).subscribe({
      next: (result) => {
        this.scanResult.set(result);
        this.selectedScanCPE.set(result.selectedCpe || null);
        this.isScanning.set(false);
      },
      error: () => {
        this.isScanning.set(false);
        this.bannerService.show('Unable to scan this asset for CVEs. Try again.', 'validation');
      },
    });
  }

  cancelScan(): void {
    if (!this.isScanning() && !this.isApplyingScan()) {
      this.isScanPanelOpen.set(false);
      this.scanResult.set(null);
      this.selectedScanCPE.set(null);
      this.pendingScanCPE.set(null);
    }
  }

  selectScanCPE(cpeName: string): void {
    if (this.isApplyingScan() || cpeName.trim() === '') {
      return;
    }
    if (cpeName === this.selectedScanCPE()) {
      return;
    }

    this.selectedScanCPE.set(cpeName);
  }

  requestScanApply(): void {
    const selectedCPE = this.selectedScanCPE();
    if (selectedCPE !== null && !this.isApplyingScan()) {
      this.pendingScanCPE.set(selectedCPE);
    }
  }

  cancelScanApply(): void {
    if (!this.isApplyingScan()) {
      this.pendingScanCPE.set(null);
    }
  }

  confirmScanApply(): void {
    const asset = this.asset();
    const selectedCPE = this.pendingScanCPE();
    if (asset === null || selectedCPE === null || this.isApplyingScan()) {
      return;
    }

    this.isApplyingScan.set(true);
    this.assetsService
      .applyCVEScan(asset.id, selectedCPE)
      .pipe(
        switchMap((response) =>
          this.vulnerabilitiesService.getVulnerabilities().pipe(
            map((vulnerabilities) => ({ response, vulnerabilities })),
            catchError(() => of({ response, vulnerabilities: null })),
          ),
        ),
      )
      .subscribe({
        next: ({ response, vulnerabilities: refreshedVulnerabilities }) => {
          this.asset.set(response.asset);
          const attachedVulnerabilities = this.withRefreshedAffectedAssetCounts(
            response.asset.vulnerabilities ?? [],
            refreshedVulnerabilities,
          );
          this.vulnerabilities.set(attachedVulnerabilities);
          if (refreshedVulnerabilities !== null) {
            this.allVulnerabilities.set(refreshedVulnerabilities);
          } else {
            this.mergeVulnerabilities(attachedVulnerabilities);
          }
          this.isApplyingScan.set(false);
          this.isScanPanelOpen.set(false);
          this.scanResult.set(null);
          this.selectedScanCPE.set(null);
          this.pendingScanCPE.set(null);
          this.bannerService.show('CVE findings attached successfully.', 'success');
        },
        error: () => {
          this.isApplyingScan.set(false);
          this.bannerService.show('Unable to attach the CVE findings. Try again.', 'validation');
        },
      });
  }

  requestAttachment(vulnerability: Vulnerability): void {
    if (!this.isAttaching() && !this.isDetaching()) {
      this.pendingAttachment.set(vulnerability);
    }
  }

  cancelAttachment(): void {
    if (!this.isAttaching()) {
      this.pendingAttachment.set(null);
    }
  }

  confirmAttachment(): void {
    const asset = this.asset();
    const vulnerability = this.pendingAttachment();
    if (asset === null || vulnerability === null || this.isAttaching()) {
      return;
    }

    this.isAttaching.set(true);
    this.assetsService.assignVulnerability(asset.id, vulnerability.id).subscribe({
      next: (updatedAsset) => {
        const attachedVulnerability = {
          ...vulnerability,
          affectedAssetCount: vulnerability.affectedAssetCount + 1,
        };
        this.asset.set(updatedAsset);
        this.vulnerabilities.update((current) => [...current, attachedVulnerability]);
        this.mergeVulnerabilities([attachedVulnerability]);
        this.pendingAttachment.set(null);
        this.isAttaching.set(false);
        this.bannerService.show('Vulnerability attached successfully.', 'success');
      },
      error: () => {
        this.isAttaching.set(false);
        this.bannerService.show('Unable to attach vulnerability. Try again.', 'validation');
      },
    });
  }

  requestDetachment(vulnerability: Vulnerability): void {
    if (!this.isAttaching() && !this.isDetaching()) {
      this.pendingDetachment.set(vulnerability);
    }
  }

  cancelDetachment(): void {
    if (!this.isDetaching()) {
      this.pendingDetachment.set(null);
    }
  }

  confirmDetachment(): void {
    const asset = this.asset();
    const vulnerability = this.pendingDetachment();
    if (asset === null || vulnerability === null || this.isDetaching()) {
      return;
    }

    this.isDetaching.set(true);
    this.assetsService.removeVulnerability(asset.id, vulnerability.id).subscribe({
      next: (updatedAsset) => {
        const detachedVulnerability = {
          ...vulnerability,
          affectedAssetCount: Math.max(0, vulnerability.affectedAssetCount - 1),
        };
        this.asset.set(updatedAsset);
        this.vulnerabilities.update((current) =>
          current.filter((currentVulnerability) => currentVulnerability.id !== vulnerability.id),
        );
        this.mergeVulnerabilities([detachedVulnerability]);
        this.pendingDetachment.set(null);
        this.isDetaching.set(false);
        this.bannerService.show('Vulnerability detached successfully.', 'success');
      },
      error: () => {
        this.isDetaching.set(false);
        this.bannerService.show('Unable to detach vulnerability. Try again.', 'validation');
      },
    });
  }

  goBack(): void {
    this.location.back();
  }

  private mergeVulnerabilities(updatedVulnerabilities: Vulnerability[]): void {
    const updatedByID = new Map(
      updatedVulnerabilities.map((vulnerability) => [vulnerability.id, vulnerability]),
    );

    this.allVulnerabilities.update((current) => {
      const merged = current.map(
        (vulnerability) => updatedByID.get(vulnerability.id) ?? vulnerability,
      );
      const existingIDs = new Set(current.map((vulnerability) => vulnerability.id));
      return [
        ...merged,
        ...updatedVulnerabilities.filter((vulnerability) => !existingIDs.has(vulnerability.id)),
      ];
    });
  }

  private withRefreshedAffectedAssetCounts(
    attachedVulnerabilities: Vulnerability[],
    refreshedVulnerabilities: Vulnerability[] | null,
  ): Vulnerability[] {
    if (refreshedVulnerabilities === null) {
      return attachedVulnerabilities;
    }

    const refreshedByID = new Map(
      refreshedVulnerabilities.map((vulnerability) => [vulnerability.id, vulnerability]),
    );
    return attachedVulnerabilities.map(
      (vulnerability) => refreshedByID.get(vulnerability.id) ?? vulnerability,
    );
  }
}

// Authenticated page that lists the assets visible to the current user.
import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { Subscription } from 'rxjs';

import {
  DataTableCellAction,
  DataTableColumn,
  DataTableComponent,
} from '../../components/data-table/data-table';
import { ConfirmationDialogComponent } from '../../components/confirmation-dialog/confirmation-dialog';
import { TableToolbarComponent } from '../../components/table-toolbar/table-toolbar';
import { PaginationComponent } from '../../components/pagination/pagination';
import { TopMenuComponent } from '../../components/top-menu/top-menu';
import { AuthService } from '../../services/auth/auth';
import {
  Asset,
  AssetListQuery,
  AssetSortField,
  AssetsService,
  CreateAssetRequest,
  SortDirection,
  VulnerabilityFilterMode,
} from '../../services/assets/assets';
import { BannerService } from '../../services/banner/banner';
import { semanticLevelClass } from '../../utils/semantic-level';

@Component({
  selector: 'app-assets-page',
  standalone: true,
  imports: [
    CommonModule,
    ConfirmationDialogComponent,
    DataTableComponent,
    PaginationComponent,
    ReactiveFormsModule,
    TableToolbarComponent,
    TopMenuComponent,
  ],
  templateUrl: './assets.html',
  styleUrl: './assets.css',
})
export class AssetsPage {
  private readonly authService = inject(AuthService);
  private readonly assetsService = inject(AssetsService);
  private readonly bannerService = inject(BannerService);
  private readonly formBuilder = inject(FormBuilder);
  private readonly router = inject(Router);
  private assetLoadSubscription?: Subscription;

  readonly session = this.authService.session;
  readonly assets = signal<Asset[]>([]);
  readonly currentPage = signal(1);
  readonly pageSize = signal(6);
  readonly totalCount = signal(0);
  readonly totalPages = signal(0);
  readonly searchQuery = signal('');
  readonly isAdvancedFiltersOpen = signal(false);
  readonly isSortOpen = signal(false);
  readonly isLoading = signal(true);
  readonly hasLoadError = signal(false);
  readonly isCreating = signal(false);
  readonly isCreateConfirmationOpen = signal(false);
  readonly isDeleting = signal(false);
  readonly isCreateOpen = signal(false);
  readonly assetPendingDeletion = signal<Asset | null>(null);
  readonly createMode = signal<'manual' | 'ai' | null>(null);
  readonly createForm = this.formBuilder.nonNullable.group({
    name: ['', [Validators.required, Validators.maxLength(200)]],
    type: ['', [Validators.required, Validators.maxLength(100)]],
    description: ['', Validators.maxLength(5000)],
    operatingSystem: ['', Validators.maxLength(100)],
    vendor: ['', [Validators.required, Validators.maxLength(100)]],
    product: ['', [Validators.required, Validators.maxLength(100)]],
    version: ['', [Validators.required, Validators.maxLength(100)]],
    owner: ['', Validators.maxLength(200)],
    criticality: ['Medium', Validators.required],
  });
  readonly filtersForm = this.formBuilder.nonNullable.group({
    criticality: [''],
    riskLevel: [''],
    type: [''],
    owner: [''],
    operatingSystem: [''],
    vendor: [''],
    product: [''],
    version: [''],
    vulnerabilityMode: ['any' as VulnerabilityFilterMode],
    vulnerabilityValue: [''],
    sortField: ['name' as AssetSortField],
    sortDirection: ['asc' as SortDirection],
  });
  readonly criticalityOptions = ['Low', 'Medium', 'High', 'Critical'];
  readonly riskLevelOptions = ['Critical', 'High', 'Medium', 'Low'];
  readonly typeOptions = computed(() => this.uniqueAssetValues((asset) => asset.type));
  readonly ownerOptions = computed(() => this.uniqueAssetValues((asset) => asset.owner));
  readonly operatingSystemOptions = computed(() =>
    this.uniqueAssetValues((asset) => asset.operatingSystem),
  );
  readonly vendorOptions = computed(() => this.uniqueAssetValues((asset) => asset.vendor));
  readonly productOptions = computed(() => this.uniqueAssetValues((asset) => asset.product));
  readonly versionOptions = computed(() => this.uniqueAssetValues((asset) => asset.version));
  readonly assetColumns: readonly DataTableColumn<Asset>[] = [
    {
      key: 'name',
      label: 'Name',
      cellValue: (asset) => asset.name,
      cellType: 'action',
      width: '55%',
    },
    {
      key: 'riskLevel',
      label: 'Risk level',
      cellValue: (asset) => asset.riskLevel || 'Low',
      cellClass: (asset) => semanticLevelClass(asset.riskLevel || 'Low'),
    },
    {
      key: 'criticality',
      label: 'Criticality',
      cellValue: (asset) => asset.criticality,
    },
    {
      key: 'vulnerabilityCount',
      label: 'Vulnerabilities',
      cellValue: (asset) => String(asset.vulnerabilityCount),
      cellType: 'action',
    },
    {
      key: 'delete',
      label: 'Remove',
      cellValue: () => '',
      cellType: 'delete',
      width: '3.5rem',
    },
  ];
  readonly assetRowKey = (asset: Asset): string => asset.id;

  constructor() {
    this.filtersForm.valueChanges
      .pipe(takeUntilDestroyed())
      .subscribe(() => this.resetToFirstPage());
    this.loadAssets();
  }

  async openAsset(assetID: string): Promise<void> {
    await this.router.navigate(['/assets', assetID]);
  }

  async openAssetVulnerabilities(assetID: string): Promise<void> {
    await this.router.navigate(['/assets', assetID, 'vulnerabilities']);
  }

  async handleTableAction(action: DataTableCellAction<Asset>): Promise<void> {
    if (action.column.key === 'name') {
      await this.openAsset(action.row.id);
      return;
    }

    if (action.column.key === 'vulnerabilityCount') {
      await this.openAssetVulnerabilities(action.row.id);
      return;
    }

    if (action.column.key === 'delete') {
      this.assetPendingDeletion.set(action.row);
    }
  }

  cancelAssetDeletion(): void {
    if (!this.isDeleting()) {
      this.assetPendingDeletion.set(null);
    }
  }

  confirmAssetDeletion(): void {
    const asset = this.assetPendingDeletion();
    if (asset === null || this.isDeleting()) {
      return;
    }

    this.isDeleting.set(true);
    this.assetsService.deleteAsset(asset.id).subscribe({
      next: () => {
        this.loadAssets();
        this.assetPendingDeletion.set(null);
        this.isDeleting.set(false);
        this.bannerService.show('Asset deleted successfully.', 'success');
      },
      error: () => {
        this.isDeleting.set(false);
        this.bannerService.show('Unable to delete asset. Try again.', 'validation');
      },
    });
  }

  selectCreateMode(mode: 'manual' | 'ai'): void {
    this.createMode.set(mode);
    this.isCreateOpen.set(true);
  }

  closeCreatePanel(): void {
    if (!this.isCreating()) {
      this.createMode.set(null);
      this.isCreateOpen.set(false);
    }
  }

  updateSearchQuery(query: string): void {
    this.searchQuery.set(query);
    this.resetToFirstPage();
  }

  toggleAdvancedFilters(): void {
    this.isAdvancedFiltersOpen.update((currentValue) => !currentValue);
  }

  toggleSort(): void {
    this.isSortOpen.update((currentValue) => !currentValue);
  }

  clearFilters(): void {
    this.searchQuery.set('');
    this.isAdvancedFiltersOpen.set(false);
    this.isSortOpen.set(false);
    this.filtersForm.reset(
      {
        criticality: '',
        riskLevel: '',
        type: '',
        owner: '',
        operatingSystem: '',
        vendor: '',
        product: '',
        version: '',
        vulnerabilityMode: 'any',
        vulnerabilityValue: '',
        sortField: 'name',
        sortDirection: 'asc',
      },
      { emitEvent: false },
    );
    this.resetToFirstPage();
  }

  createAsset(): void {
    this.bannerService.clear();

    if (this.createForm.invalid) {
      this.createForm.markAllAsTouched();
      this.bannerService.show('Complete all required fields.', 'validation');
      return;
    }

    this.isCreateConfirmationOpen.set(true);
  }

  cancelCreate(): void {
    if (!this.isCreating()) {
      this.isCreateConfirmationOpen.set(false);
    }
  }

  confirmCreate(): void {
    if (this.isCreating() || this.createForm.invalid) {
      return;
    }

    this.isCreateConfirmationOpen.set(false);
    this.isCreating.set(true);
    const formValue = this.createForm.getRawValue();
    const request: CreateAssetRequest = {
      name: formValue.name.trim(),
      type: formValue.type.trim(),
      description: formValue.description.trim() || undefined,
      operatingSystem: formValue.operatingSystem.trim() || undefined,
      vendor: formValue.vendor.trim(),
      product: formValue.product.trim(),
      version: formValue.version.trim(),
      owner: formValue.owner.trim() || undefined,
      criticality: formValue.criticality,
    };

    this.submitAssetCreation(request);
  }

  private submitAssetCreation(request: CreateAssetRequest): void {
    this.isCreating.set(true);
    this.assetsService.createAsset(request).subscribe({
      next: () => {
        this.createForm.reset({
          name: '',
          type: '',
          description: '',
          operatingSystem: '',
          vendor: '',
          product: '',
          version: '',
          owner: '',
          criticality: 'Medium',
        });
        this.createMode.set(null);
        this.isCreateOpen.set(false);
        this.isCreating.set(false);
        this.resetToFirstPage();
        this.bannerService.show('Asset created successfully.', 'success');
      },
      error: () => {
        this.isCreating.set(false);
        this.bannerService.show('Unable to create asset. Try again.', 'validation');
      },
    });
  }

  changePage(page: number): void {
    this.currentPage.set(page);
    this.loadAssets();
  }

  private resetToFirstPage(): void {
    this.currentPage.set(1);
    this.loadAssets();
  }

  private loadAssets(): void {
    this.assetLoadSubscription?.unsubscribe();
    this.isLoading.set(true);
    this.hasLoadError.set(false);
    this.assetLoadSubscription = this.assetsService.getAssetPage(this.assetListQuery()).subscribe({
      next: (response) => {
        if (response.assets.length === 0 && response.pagination.page > 1) {
          this.currentPage.set(Math.max(1, response.pagination.totalPages));
          this.loadAssets();
          return;
        }

        this.assets.set(response.assets);
        this.currentPage.set(response.pagination.page);
        this.pageSize.set(response.pagination.pageSize);
        this.totalCount.set(response.pagination.totalCount);
        this.totalPages.set(response.pagination.totalPages);
        this.isLoading.set(false);
      },
      error: () => {
        this.hasLoadError.set(true);
        this.isLoading.set(false);
      },
    });
  }

  private assetListQuery(): AssetListQuery {
    const filters = this.filtersForm.getRawValue();
    const vulnerabilityValue = filters.vulnerabilityValue.trim();
    return {
      page: this.currentPage(),
      search: this.searchQuery(),
      criticality: filters.criticality,
      riskLevel: filters.riskLevel,
      type: filters.type,
      owner: filters.owner,
      operatingSystem: filters.operatingSystem,
      vendor: filters.vendor,
      product: filters.product,
      version: filters.version,
      vulnerabilityMode: filters.vulnerabilityMode,
      vulnerabilityValue: vulnerabilityValue === '' ? undefined : Number(vulnerabilityValue),
      sortField: filters.sortField,
      sortDirection: filters.sortDirection,
    };
  }

  private uniqueAssetValues(selector: (asset: Asset) => string | null | undefined): string[] {
    return [
      ...new Set(
        this.assets()
          .map(selector)
          .filter((value): value is string => !!value),
      ),
    ].sort((leftValue, rightValue) => leftValue.localeCompare(rightValue));
  }
}

// Authenticated page that lists the assets visible to the current user.
import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { startWith } from 'rxjs';

import {
  DataTableCellAction,
  DataTableColumn,
  DataTableComponent,
} from '../../components/data-table/data-table';
import { ConfirmationDialogComponent } from '../../components/confirmation-dialog/confirmation-dialog';
import { TableToolbarComponent } from '../../components/table-toolbar/table-toolbar';
import { TopMenuComponent } from '../../components/top-menu/top-menu';
import { AuthService } from '../../services/auth/auth';
import { Asset, AssetsService, CreateAssetRequest } from '../../services/assets/assets';
import { BannerService } from '../../services/banner/banner';
import { semanticLevelClass } from '../../utils/semantic-level';

type VulnerabilityFilterMode = 'any' | 'atLeast' | 'atMost' | 'exactly';
type AssetSortField =
  | 'name'
  | 'criticality'
  | 'riskLevel'
  | 'vulnerabilityCount'
  | 'type'
  | 'owner'
  | 'operatingSystem'
  | 'vendor'
  | 'product'
  | 'version';
type SortDirection = 'asc' | 'desc';

@Component({
  selector: 'app-assets-page',
  standalone: true,
  imports: [
    CommonModule,
    ConfirmationDialogComponent,
    DataTableComponent,
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

  readonly session = this.authService.session;
  readonly assets = signal<Asset[]>([]);
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
  readonly filtersFormValue = toSignal(
    this.filtersForm.valueChanges.pipe(startWith(this.filtersForm.getRawValue())),
    { initialValue: this.filtersForm.getRawValue() },
  );
  readonly criticalityOptions = ['Low', 'Medium', 'High', 'Critical'];
  readonly riskLevelOptions = ['Critical', 'High', 'Medium', 'Low'];
  readonly filteredAssets = computed(() => {
    const normalizedQuery = this.searchQuery().trim().toLocaleLowerCase();
    const formValue = this.filtersFormValue();
    const criticality = this.coerceFilterText(formValue.criticality);
    const riskLevel = this.coerceFilterText(formValue.riskLevel);
    const type = this.coerceFilterText(formValue.type);
    const owner = this.coerceFilterText(formValue.owner);
    const operatingSystem = this.coerceFilterText(formValue.operatingSystem);
    const vendor = this.coerceFilterText(formValue.vendor);
    const product = this.coerceFilterText(formValue.product);
    const version = this.coerceFilterText(formValue.version);
    const vulnerabilityMode = this.coerceVulnerabilityMode(formValue.vulnerabilityMode);
    const vulnerabilityValue = this.coerceFilterText(formValue.vulnerabilityValue);
    const sortField = this.coerceSortField(formValue.sortField);
    const sortDirection = this.coerceSortDirection(formValue.sortDirection);
    const normalizedType = type.trim().toLocaleLowerCase();
    const normalizedOwner = owner.trim().toLocaleLowerCase();
    const normalizedOperatingSystem = operatingSystem.trim().toLocaleLowerCase();
    const normalizedVendor = vendor.trim().toLocaleLowerCase();
    const normalizedProduct = product.trim().toLocaleLowerCase();
    const normalizedVersion = version.trim().toLocaleLowerCase();
    const parsedVulnerabilityValue =
      vulnerabilityValue.trim() === '' ? null : Number(vulnerabilityValue);

    const filteredAssets = this.assets().filter((asset) => {
      if (normalizedQuery !== '' && !asset.name.toLocaleLowerCase().includes(normalizedQuery)) {
        return false;
      }

      if (criticality !== '' && asset.criticality !== criticality) {
        return false;
      }

      const assetRiskLevel = asset.riskLevel || 'Low';
      if (riskLevel !== '' && assetRiskLevel !== riskLevel) {
        return false;
      }

      if (normalizedType !== '' && asset.type.toLocaleLowerCase() !== normalizedType) {
        return false;
      }

      if (normalizedOwner !== '' && asset.owner.toLocaleLowerCase() !== normalizedOwner) {
        return false;
      }

      if (
        normalizedOperatingSystem !== '' &&
        (asset.operatingSystem || '').toLocaleLowerCase() !== normalizedOperatingSystem
      ) {
        return false;
      }

      if (
        normalizedVendor !== '' &&
        (asset.vendor || '').toLocaleLowerCase() !== normalizedVendor
      ) {
        return false;
      }

      if (
        normalizedProduct !== '' &&
        (asset.product || '').toLocaleLowerCase() !== normalizedProduct
      ) {
        return false;
      }

      if (
        normalizedVersion !== '' &&
        (asset.version || '').toLocaleLowerCase() !== normalizedVersion
      ) {
        return false;
      }

      if (
        parsedVulnerabilityValue !== null &&
        !Number.isNaN(parsedVulnerabilityValue) &&
        !this.matchesVulnerabilityFilter(
          asset.vulnerabilityCount,
          vulnerabilityMode,
          parsedVulnerabilityValue,
        )
      ) {
        return false;
      }

      return true;
    });

    return [...filteredAssets].sort((leftAsset, rightAsset) => {
      const comparison = this.compareAssets(leftAsset, rightAsset, sortField);
      return sortDirection === 'asc' ? comparison : comparison * -1;
    });
  });
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
        this.assets.update((assets) =>
          assets.filter((currentAsset) => currentAsset.id !== asset.id),
        );
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
    this.filtersForm.reset({
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
    });
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
      next: (asset) => {
        this.assets.update((assets) => [...assets, asset]);
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
        this.bannerService.show('Asset created successfully.', 'success');
      },
      error: () => {
        this.isCreating.set(false);
        this.bannerService.show('Unable to create asset. Try again.', 'validation');
      },
    });
  }

  private loadAssets(): void {
    this.assetsService.getAssets().subscribe({
      next: (assets) => {
        this.assets.set(assets);
        this.isLoading.set(false);
      },
      error: () => {
        this.hasLoadError.set(true);
        this.isLoading.set(false);
      },
    });
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

  private matchesVulnerabilityFilter(
    vulnerabilityCount: number,
    mode: VulnerabilityFilterMode,
    targetValue: number,
  ): boolean {
    if (mode === 'any') {
      return true;
    }

    if (mode === 'atLeast') {
      return vulnerabilityCount >= targetValue;
    }

    if (mode === 'atMost') {
      return vulnerabilityCount <= targetValue;
    }

    return vulnerabilityCount === targetValue;
  }

  private compareAssets(leftAsset: Asset, rightAsset: Asset, sortField: AssetSortField): number {
    if (sortField === 'vulnerabilityCount') {
      return leftAsset.vulnerabilityCount - rightAsset.vulnerabilityCount;
    }

    const leftValue = this.assetSortValue(leftAsset, sortField);
    const rightValue = this.assetSortValue(rightAsset, sortField);
    return leftValue.localeCompare(rightValue, undefined, {
      numeric: true,
      sensitivity: 'base',
    });
  }

  private assetSortValue(asset: Asset, sortField: AssetSortField): string {
    if (sortField === 'riskLevel') {
      return asset.riskLevel || 'Low';
    }

    if (sortField === 'operatingSystem') {
      return asset.operatingSystem || '';
    }

    if (sortField === 'vendor') {
      return asset.vendor || '';
    }

    if (sortField === 'product') {
      return asset.product || '';
    }

    if (sortField === 'version') {
      return asset.version || '';
    }

    return String(asset[sortField]);
  }

  private coerceFilterText(value: unknown): string {
    if (typeof value === 'string') {
      return value;
    }

    if (typeof value === 'number') {
      return String(value);
    }

    return '';
  }

  private coerceVulnerabilityMode(value: unknown): VulnerabilityFilterMode {
    if (value === 'any' || value === 'atLeast' || value === 'atMost' || value === 'exactly') {
      return value;
    }

    return 'any';
  }

  private coerceSortField(value: unknown): AssetSortField {
    if (
      value === 'name' ||
      value === 'criticality' ||
      value === 'riskLevel' ||
      value === 'vulnerabilityCount' ||
      value === 'type' ||
      value === 'owner' ||
      value === 'operatingSystem' ||
      value === 'vendor' ||
      value === 'product' ||
      value === 'version'
    ) {
      return value;
    }

    return 'name';
  }

  private coerceSortDirection(value: unknown): SortDirection {
    if (value === 'asc' || value === 'desc') {
      return value;
    }

    return 'asc';
  }
}

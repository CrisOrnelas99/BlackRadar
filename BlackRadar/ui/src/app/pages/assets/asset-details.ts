// Authenticated page that displays all currently available details for one asset.
import { CommonModule } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { EMPTY, map, switchMap } from 'rxjs';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';

import { ConfirmationDialogComponent } from '../../components/confirmation-dialog/confirmation-dialog';
import { TopMenuComponent } from '../../components/top-menu/top-menu';
import { AuthService } from '../../services/auth/auth';
import { Asset, AssetsService, ManualAssetRequest } from '../../services/assets/assets';
import { BannerService } from '../../services/banner/banner';

@Component({
  selector: 'app-asset-details-page',
  standalone: true,
  imports: [
    CommonModule,
    ConfirmationDialogComponent,
    ReactiveFormsModule,
    RouterLink,
    TopMenuComponent,
  ],
  templateUrl: './asset-details.html',
  styleUrl: './asset-details.css',
})
export class AssetDetailsPage {
  private readonly authService = inject(AuthService);
  private readonly activatedRoute = inject(ActivatedRoute);
  private readonly assetsService = inject(AssetsService);
  private readonly bannerService = inject(BannerService);
  private readonly formBuilder = inject(FormBuilder);
  private readonly router = inject(Router);

  readonly session = this.authService.session;
  readonly asset = signal<Asset | null>(null);
  readonly isLoading = signal(true);
  readonly hasLoadError = signal(false);
  readonly isEditing = signal(false);
  readonly isSaving = signal(false);
  readonly isDeleting = signal(false);
  readonly isSaveConfirmationOpen = signal(false);
  readonly isDeleteConfirmationOpen = signal(false);
  readonly editForm = this.formBuilder.nonNullable.group({
    name: ['', [Validators.required, Validators.maxLength(200)]],
    type: ['', [Validators.required, Validators.maxLength(100)]],
    operatingSystem: ['', Validators.maxLength(100)],
    vendor: ['', Validators.maxLength(100)],
    product: ['', Validators.maxLength(100)],
    version: ['', Validators.maxLength(100)],
    owner: ['', [Validators.required, Validators.maxLength(200)]],
    criticality: ['Medium', Validators.required],
  });

  constructor() {
    this.activatedRoute.paramMap
      .pipe(
        map((paramMap) => paramMap.get('id')),
        switchMap((assetID) => {
          this.isLoading.set(true);
          this.hasLoadError.set(false);
          this.asset.set(null);

          if (!assetID) {
            this.hasLoadError.set(true);
            this.isLoading.set(false);
            return EMPTY;
          }

          return this.assetsService.getAsset(assetID);
        }),
      )
      .subscribe({
        next: (asset) => {
          this.asset.set(asset);
          this.populateEditForm(asset);
          this.isLoading.set(false);
        },
        error: () => {
          this.hasLoadError.set(true);
          this.isLoading.set(false);
        },
      });
  }

  openEditor(): void {
    const currentAsset = this.asset();
    if (currentAsset === null) {
      return;
    }

    this.populateEditForm(currentAsset);
    this.bannerService.clear();
    this.isEditing.set(true);
  }

  closeEditor(): void {
    if (!this.isSaving() && !this.isDeleting()) {
      this.isEditing.set(false);
    }
  }

  saveAsset(): void {
    const currentAsset = this.asset();
    if (
      currentAsset === null ||
      this.isSaving() ||
      this.isDeleting() ||
      this.isDeleteConfirmationOpen()
    ) {
      return;
    }

    this.bannerService.clear();
    if (this.editForm.invalid) {
      this.editForm.markAllAsTouched();
      this.bannerService.show('Complete all required fields.', 'validation');
      return;
    }

    this.isSaveConfirmationOpen.set(true);
  }

  cancelSave(): void {
    if (!this.isSaving()) {
      this.isSaveConfirmationOpen.set(false);
    }
  }

  confirmSave(): void {
    const currentAsset = this.asset();
    if (currentAsset === null || this.isSaving() || this.isDeleting()) {
      return;
    }

    this.isSaveConfirmationOpen.set(false);
    this.isSaving.set(true);
    const formValue = this.editForm.getRawValue();
    const request: ManualAssetRequest = {
      name: formValue.name.trim(),
      type: formValue.type.trim(),
      operatingSystem: formValue.operatingSystem.trim() || undefined,
      vendor: formValue.vendor.trim() || undefined,
      product: formValue.product.trim() || undefined,
      version: formValue.version.trim() || undefined,
      owner: formValue.owner.trim(),
      criticality: formValue.criticality,
    };

    this.assetsService.updateAsset(currentAsset.id, request).subscribe({
      next: (updatedAsset) => {
        this.asset.set(updatedAsset);
        this.populateEditForm(updatedAsset);
        this.isSaving.set(false);
        this.isEditing.set(false);
        this.bannerService.show('Asset updated successfully.', 'success');
      },
      error: () => {
        this.isSaving.set(false);
        this.bannerService.show('Unable to update asset. Try again.', 'validation');
      },
    });
  }

  requestDeletion(): void {
    if (!this.isSaving() && !this.isDeleting() && !this.isSaveConfirmationOpen()) {
      this.isDeleteConfirmationOpen.set(true);
    }
  }

  cancelDeletion(): void {
    if (!this.isDeleting()) {
      this.isDeleteConfirmationOpen.set(false);
    }
  }

  confirmDeletion(): void {
    const currentAsset = this.asset();
    if (currentAsset === null || this.isDeleting() || this.isSaving()) {
      return;
    }

    this.isDeleting.set(true);
    this.assetsService.deleteAsset(currentAsset.id).subscribe({
      next: () => {
        this.isDeleteConfirmationOpen.set(false);
        this.isDeleting.set(false);
        this.bannerService.show('Asset deleted successfully.', 'success');
        void this.router.navigate(['/assets']);
      },
      error: () => {
        this.isDeleting.set(false);
        this.bannerService.show('Unable to delete asset. Try again.', 'validation');
      },
    });
  }

  private populateEditForm(asset: Asset): void {
    this.editForm.reset({
      name: asset.name,
      type: asset.type,
      operatingSystem: asset.operatingSystem || '',
      vendor: asset.vendor || '',
      product: asset.product || '',
      version: asset.version || '',
      owner: asset.owner,
      criticality: asset.criticality,
    });
  }
}

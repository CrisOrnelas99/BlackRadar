// Authenticated page that lists the assets visible to the current user.
import { CommonModule } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
import { Router } from '@angular/router';

import {
  DataTableCellAction,
  DataTableColumn,
  DataTableComponent,
} from '../../components/data-table/data-table';
import { TopMenuComponent } from '../../components/top-menu/top-menu';
import { AuthService } from '../../services/auth/auth';
import { Asset, AssetsService } from '../../services/assets/assets';

@Component({
  selector: 'app-assets-page',
  standalone: true,
  imports: [CommonModule, DataTableComponent, TopMenuComponent],
  templateUrl: './assets.html',
  styleUrl: './assets.css',
})
export class AssetsPage {
  private readonly authService = inject(AuthService);
  private readonly assetsService = inject(AssetsService);
  private readonly router = inject(Router);

  readonly session = this.authService.session;
  readonly assets = signal<Asset[]>([]);
  readonly isLoading = signal(true);
  readonly hasLoadError = signal(false);
  readonly assetColumns: readonly DataTableColumn<Asset>[] = [
    {
      key: 'name',
      label: 'Name',
      cellValue: (asset) => asset.name,
      cellType: 'action',
      width: '55%',
    },
    {
      key: 'criticality',
      label: 'Criticality',
      cellValue: (asset) => asset.criticality,
    },
    {
      key: 'riskLevel',
      label: 'Risk level',
      cellValue: (asset) => asset.riskLevel || 'Not assessed',
    },
    {
      key: 'vulnerabilityCount',
      label: 'Vulnerabilities',
      cellValue: (asset) => String(asset.vulnerabilityCount),
    },
  ];

  // Loads the authenticated user's assets when the page is created.
  constructor() {
    this.loadAssets();
  }

  // Navigates to the details page for the selected asset.
  async openAsset(assetID: string): Promise<void> {
    await this.router.navigate(['/assets', assetID]);
  }

  // Handles actions emitted by the reusable table component.
  async handleTableAction(action: DataTableCellAction<Asset>): Promise<void> {
    if (action.column.key === 'name') {
      await this.openAsset(action.row.id);
    }
  }

  // Requests the user's assets and updates the page state for success or failure.
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
}

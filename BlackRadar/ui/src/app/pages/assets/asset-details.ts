// Authenticated page that displays all currently available details for one asset.
import { CommonModule } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { EMPTY, map, switchMap } from 'rxjs';

import { TopMenuComponent } from '../../components/top-menu/top-menu';
import { AuthService } from '../../services/auth/auth';
import { Asset, AssetsService } from '../../services/assets/assets';

@Component({
  selector: 'app-asset-details-page',
  standalone: true,
  imports: [CommonModule, RouterLink, TopMenuComponent],
  templateUrl: './asset-details.html',
  styleUrl: './asset-details.css',
})
export class AssetDetailsPage {
  private readonly authService = inject(AuthService);
  private readonly activatedRoute = inject(ActivatedRoute);
  private readonly assetsService = inject(AssetsService);

  readonly session = this.authService.session;
  readonly asset = signal<Asset | null>(null);
  readonly isLoading = signal(true);
  readonly hasLoadError = signal(false);

  // Loads the asset identified by the current route for the authenticated user.
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
          this.isLoading.set(false);
        },
        error: () => {
          this.hasLoadError.set(true);
          this.isLoading.set(false);
        },
      });
  }
}

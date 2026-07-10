// Banner service that manages transient status messages across route changes.
import { Injectable, NgZone, inject, signal } from '@angular/core';

import { StatusBannerTone } from '../../components/status-banner/status-banner.types';

export interface BannerState {
  message: string;
  tone: StatusBannerTone;
}

@Injectable({
  providedIn: 'root',
})
export class BannerService {
  private dismissTimer: ReturnType<typeof setTimeout> | null = null;
  private readonly ngZone = inject(NgZone);

  readonly banner = signal<BannerState | null>(null);

  // Displays a banner for the requested duration and replaces any active banner.
  show(message: string, tone: StatusBannerTone, durationMs = 4000): void {
    this.clear();
    this.banner.set({ message, tone });
    this.dismissTimer = setTimeout(() => {
      this.ngZone.run(() => {
        this.banner.set(null);
        this.dismissTimer = null;
      });
    }, durationMs);
  }

  // Removes the active banner immediately and clears its pending dismiss timer.
  clear(): void {
    if (this.dismissTimer !== null) {
      clearTimeout(this.dismissTimer);
      this.dismissTimer = null;
    }

    this.banner.set(null);
  }
}

// Root application component that renders the shell, route content, and global banner host.
import { Component, inject } from '@angular/core';
import { RouterOutlet } from '@angular/router';

import { StatusBannerComponent } from './components/status-banner/status-banner';
import { BannerService } from './services/banner/banner';
import { AuthService } from './services/auth/auth';

@Component({
  selector: 'app-root',
  imports: [RouterOutlet, StatusBannerComponent],
  templateUrl: './app.html',
  styleUrl: './app.css',
})
export class App {
  private readonly authService = inject(AuthService);
  readonly bannerService = inject(BannerService);

  constructor() {
    // Refreshes the session signal after browser startup so the shared header reflects stored auth state.
    this.authService.syncSessionFromStorage();
  }
}

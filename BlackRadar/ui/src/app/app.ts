// Root application component that renders the shell, route content, and global banner host.
import { Component, inject } from '@angular/core';
import { RouterOutlet } from '@angular/router';

import { StatusBannerComponent } from './components/status-banner/status-banner';
import { BannerService } from './services/banner/banner';
import { ThemeService } from './services/theme/theme';

@Component({
  selector: 'app-root',
  imports: [RouterOutlet, StatusBannerComponent],
  templateUrl: './app.html',
  styleUrl: './app.css',
})
export class App {
  readonly bannerService = inject(BannerService);
  // Initializes the persisted theme before any routed page is displayed.
  private readonly themeService = inject(ThemeService);
}

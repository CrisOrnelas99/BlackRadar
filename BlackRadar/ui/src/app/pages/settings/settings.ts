import { Component, inject } from '@angular/core';

import { PageLayoutComponent } from '../../components/page-layout/page-layout';
import { TopMenuComponent } from '../../components/top-menu/top-menu';
import { AuthService } from '../../services/auth/auth';
import { ThemeMode, ThemeService } from '../../services/theme/theme';

@Component({
  selector: 'app-settings-page',
  standalone: true,
  imports: [PageLayoutComponent, TopMenuComponent],
  templateUrl: './settings.html',
  styleUrl: './settings.css',
})
export class SettingsPage {
  private readonly authService = inject(AuthService);
  readonly themeService = inject(ThemeService);
  readonly session = this.authService.session;

  // Applies the browser's selected appearance from the native switch control.
  updateTheme(event: Event): void {
    const control = event.target;
    if (!(control instanceof HTMLInputElement)) {
      return;
    }

    const theme: ThemeMode = control.checked ? 'dark' : 'light';
    this.themeService.setTheme(theme);
  }
}

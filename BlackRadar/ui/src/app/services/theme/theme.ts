import { DOCUMENT, isPlatformBrowser } from '@angular/common';
import { inject, Injectable, PLATFORM_ID, signal } from '@angular/core';

export type ThemeMode = 'light' | 'dark';

const themeStorageKey = 'blackradar-theme';
const darkThemeClass = 'blackradar-dark-theme';

// Owns the non-sensitive visual theme preference for the Angular application.
@Injectable({ providedIn: 'root' })
export class ThemeService {
  private readonly document = inject(DOCUMENT);
  private readonly platformId = inject(PLATFORM_ID);

  readonly theme = signal<ThemeMode>(this.readStoredTheme());

  constructor() {
    this.applyTheme(this.theme());
  }

  // Sets the selected theme, updates the document, and persists it for the browser.
  setTheme(theme: ThemeMode): void {
    this.theme.set(theme);
    this.applyTheme(theme);

    if (!isPlatformBrowser(this.platformId)) {
      return;
    }

    try {
      window.localStorage.setItem(themeStorageKey, theme);
    } catch {
      // A storage restriction should not prevent the theme from being applied now.
    }
  }

  private readStoredTheme(): ThemeMode {
    if (!isPlatformBrowser(this.platformId)) {
      return 'light';
    }

    try {
      return window.localStorage.getItem(themeStorageKey) === 'dark' ? 'dark' : 'light';
    } catch {
      return 'light';
    }
  }

  private applyTheme(theme: ThemeMode): void {
    this.document.documentElement.classList.toggle(darkThemeClass, theme === 'dark');
  }
}

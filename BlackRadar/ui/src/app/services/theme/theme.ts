import { DOCUMENT, isPlatformBrowser } from '@angular/common';
import { effect, inject, Injectable, PLATFORM_ID, signal } from '@angular/core';

import { AuthService } from '../auth/auth';

export type ThemeMode = 'light' | 'dark';

const themeStorageKeyPrefix = 'blackradar-theme:';
const darkThemeClass = 'blackradar-dark-theme';

// Owns the non-sensitive visual theme preference for the Angular application.
@Injectable({ providedIn: 'root' })
export class ThemeService {
  private readonly document = inject(DOCUMENT);
  private readonly platformId = inject(PLATFORM_ID);
  private readonly authService = inject(AuthService);
  private activeUserId: string | null = null;

  readonly theme = signal<ThemeMode>('light');

  constructor() {
    this.setActiveUser(this.authService.session()?.user.id ?? null);
    this.applyTheme(this.theme());
    effect(() => {
      this.setActiveUser(this.authService.session()?.user.id ?? null);
    });
  }

  // Sets the selected theme, updates the document, and persists it for the browser.
  setTheme(theme: ThemeMode): void {
    this.theme.set(theme);
    this.applyTheme(theme);

    if (!isPlatformBrowser(this.platformId)) {
      return;
    }

    try {
      if (this.activeUserId) {
        window.localStorage.setItem(this.storageKey(this.activeUserId), theme);
      }
    } catch {
      // A storage restriction should not prevent the theme from being applied now.
    }
  }

  private setActiveUser(userId: string | null): void {
    if (this.activeUserId === userId) {
      return;
    }

    this.activeUserId = userId;
    const theme = this.readStoredTheme(userId);
    this.theme.set(theme);
    this.applyTheme(theme);
  }

  private readStoredTheme(userId: string | null): ThemeMode {
    if (!userId) {
      return 'light';
    }

    if (!isPlatformBrowser(this.platformId)) {
      return 'light';
    }

    try {
      return window.localStorage.getItem(this.storageKey(userId)) === 'dark' ? 'dark' : 'light';
    } catch {
      return 'light';
    }
  }

  private applyTheme(theme: ThemeMode): void {
    this.document.documentElement.classList.toggle(darkThemeClass, theme === 'dark');
  }

  private storageKey(userId: string): string {
    return `${themeStorageKeyPrefix}${userId}`;
  }
}

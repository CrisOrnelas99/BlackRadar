// Shared authenticated top menu that exposes product navigation and account actions.
import { Component, ViewEncapsulation, input, inject } from '@angular/core';
import { Router } from '@angular/router';
import { firstValueFrom } from 'rxjs';

import { BannerService } from '../../services/banner/banner';
import { AuthService, LoginResponse } from '../../services/auth/auth';
import { ConfirmationDialogComponent } from '../confirmation-dialog/confirmation-dialog';

interface NavigationItem {
  key: string;
  label: string;
  path: string;
  isActive: (currentUrl: string) => boolean;
}

@Component({
  selector: 'app-top-menu',
  standalone: true,
  imports: [ConfirmationDialogComponent],
  templateUrl: './top-menu.html',
  encapsulation: ViewEncapsulation.None,
})
export class TopMenuComponent {
  private readonly authService = inject(AuthService);
  private readonly bannerService = inject(BannerService);
  private readonly router = inject(Router);

  readonly session = input.required<LoginResponse>();
  readonly currentUrl = input<string>('');
  readonly primaryNavigationItems: ReadonlyArray<NavigationItem> = [
    {
      key: 'dashboard',
      label: 'Dashboard',
      path: '/dashboard',
      isActive: (currentUrl) => currentUrl.startsWith('/dashboard'),
    },
    {
      key: 'assets',
      label: 'Assets',
      path: '/assets',
      isActive: (currentUrl) => currentUrl === '/assets' || currentUrl.startsWith('/assets/'),
    },
    {
      key: 'vulnerabilities',
      label: 'Vulnerabilities',
      path: '/vulnerabilities',
      isActive: (currentUrl) => currentUrl.startsWith('/vulnerabilities'),
    },
  ];
  readonly accountNavigationItems: ReadonlyArray<NavigationItem> = [
    {
      key: 'profile',
      label: 'Profile',
      path: '/profile',
      isActive: (currentUrl) => currentUrl.startsWith('/profile'),
    },
    {
      key: 'settings',
      label: 'Settings',
      path: '/settings',
      isActive: (currentUrl) => currentUrl.startsWith('/settings'),
    },
  ];
  readonly adminAccountNavigationItems: ReadonlyArray<NavigationItem> = [
    ...this.accountNavigationItems,
    {
      key: 'users',
      label: 'User management',
      path: '/users',
      isActive: (currentUrl) => currentUrl.startsWith('/users'),
    },
    {
      key: 'health',
      label: 'System health',
      path: '/health',
      isActive: (currentUrl) => currentUrl.startsWith('/health'),
    },
  ];

  get visibleAccountNavigationItems(): ReadonlyArray<NavigationItem> {
    if (this.session().user.role === 'admin' || this.session().user.role === 'master') {
      return this.adminAccountNavigationItems;
    }
    return this.accountNavigationItems;
  }

  get isAccountNavigationContext(): boolean {
    const url = this.currentUrl();
    return (
      url.startsWith('/profile') ||
      url.startsWith('/settings') ||
      url.startsWith('/users') ||
      url.startsWith('/health')
    );
  }

  get isShowingAccountNavigation(): boolean {
    return this.isNavigationMenuOpen !== this.isAccountNavigationContext;
  }

  get visibleNavigationItems(): ReadonlyArray<NavigationItem> {
    return this.isShowingAccountNavigation
      ? this.visibleAccountNavigationItems
      : this.primaryNavigationItems;
  }

  isNavigationMenuOpen = false;
  isSignOutConfirmationOpen = false;

  // Returns the person label shown in the top-right trigger.
  get displayName(): string {
    return (
      this.session().user.fullName || this.session().user.username || this.session().user.email
    );
  }

  // Switches between the data and account navigation contexts.
  toggleNavigationMenu(): void {
    this.isNavigationMenuOpen = !this.isNavigationMenuOpen;
  }

  // Routes the user to the requested page and collapses any open menu state.
  async navigateTo(path: string): Promise<void> {
    this.closeMenus();
    if (this.currentUrl() === path) {
      return;
    }

    await this.router.navigateByUrl(path);
  }

  requestSignOut(): void {
    this.isSignOutConfirmationOpen = true;
  }

  cancelSignOut(): void {
    this.isSignOutConfirmationOpen = false;
  }

  async confirmSignOut(): Promise<void> {
    this.isSignOutConfirmationOpen = false;
    await this.signOut();
  }

  // Clears the session, announces the logout, and returns the user to the login page.
  async signOut(): Promise<void> {
    this.closeMenus();
    try {
      await firstValueFrom(this.authService.logout());
      this.bannerService.show('Signed out successfully.', 'success');
      await this.router.navigateByUrl('/login');
    } catch {
      this.bannerService.show('Unable to confirm sign-out. Try again.', 'error');
    }
  }

  // Resets the context switch so the current route determines the visible group.
  private closeMenus(): void {
    this.isNavigationMenuOpen = false;
  }
}

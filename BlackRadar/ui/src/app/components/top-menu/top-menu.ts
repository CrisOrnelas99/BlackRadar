// Shared authenticated top menu that exposes product navigation and account actions.
import {
  Component,
  ElementRef,
  HostListener,
  ViewEncapsulation,
  input,
  inject,
} from '@angular/core';
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
  private readonly elementRef = inject(ElementRef<HTMLElement>);
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
    if (this.session().user.role === 'admin') {
      return this.adminAccountNavigationItems;
    }
    return this.accountNavigationItems;
  }

  isNavigationMenuOpen = false;
  isSignOutConfirmationOpen = false;

  // Returns the person label shown in the top-right trigger.
  get displayName(): string {
    return (
      this.session().user.fullName || this.session().user.username || this.session().user.email
    );
  }

  // Toggles the page-navigation dropdown.
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

  // Closes open panels when the user clicks outside the menu host.
  @HostListener('document:click', ['$event'])
  handleDocumentClick(event: MouseEvent): void {
    const target = event.target;
    if (!(target instanceof Node)) {
      return;
    }

    if (this.elementRef.nativeElement.contains(target)) {
      return;
    }

    this.closeMenus();
  }

  // Closes all menu surfaces when escape is pressed.
  @HostListener('document:keydown.escape')
  handleEscape(): void {
    this.closeMenus();
  }

  // Resets both menu surfaces to their closed state.
  private closeMenus(): void {
    this.isNavigationMenuOpen = false;
  }
}

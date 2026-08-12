// Shared authenticated top menu that exposes product navigation and account actions.
import { CommonModule } from '@angular/common';
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

interface NavigationItem {
  key: string;
  label: string;
  path: string;
  isActive: (currentUrl: string) => boolean;
}

@Component({
  selector: 'app-top-menu',
  standalone: true,
  imports: [CommonModule],
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
  readonly navigationItems: ReadonlyArray<NavigationItem> = [
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

  isNavigationMenuOpen = false;
  isProfileMenuOpen = false;

  // Returns the person label shown in the top-right trigger.
  get displayName(): string {
    return (
      this.session().user.fullName || this.session().user.username || this.session().user.email
    );
  }

  // Toggles the page-navigation dropdown and closes the profile panel when needed.
  toggleNavigationMenu(): void {
    this.isNavigationMenuOpen = !this.isNavigationMenuOpen;
    if (this.isNavigationMenuOpen) {
      this.isProfileMenuOpen = false;
    }
  }

  // Toggles the profile panel and closes the page-navigation dropdown when needed.
  toggleProfileMenu(): void {
    this.isProfileMenuOpen = !this.isProfileMenuOpen;
    if (this.isProfileMenuOpen) {
      this.isNavigationMenuOpen = false;
    }
  }

  // Routes the user to the requested page and collapses any open menu state.
  async navigateTo(path: string, isActive: (currentUrl: string) => boolean): Promise<void> {
    this.closeMenus();
    if (isActive(this.currentUrl())) {
      return;
    }

    await this.router.navigateByUrl(path);
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
    this.isProfileMenuOpen = false;
  }
}

// Shared public page for safe, user-facing application error states.
import { DOCUMENT } from '@angular/common';
import { Component, inject } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';

import { AuthService } from '../../services/auth/auth';
import { PageLayoutComponent } from '../../components/page-layout/page-layout';

export type ErrorPageDefinition = {
  code: '401' | '403' | '404' | '500';
  title: string;
  message: string;
  primaryActionLabel: string;
  primaryActionUrl: string;
  canRetry?: boolean;
};

@Component({
  selector: 'app-error-page',
  standalone: true,
  imports: [PageLayoutComponent],
  templateUrl: './error-page.html',
  styleUrl: './error-page.css',
})
export class ErrorPage {
  private readonly document = inject(DOCUMENT);
  private readonly authService = inject(AuthService);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);

  readonly definition = this.route.snapshot.data['errorPage'] as ErrorPageDefinition;

  get primaryActionLabel(): string {
    return this.shouldSignIn() ? 'Go to sign in' : this.definition.primaryActionLabel;
  }

  navigateToPrimaryAction(): void {
    void this.router.navigateByUrl(this.primaryActionUrl());
  }

  retry(): void {
    const browserWindow = this.document.defaultView;

    if (browserWindow) {
      browserWindow.location.reload();
      return;
    }

    this.navigateToPrimaryAction();
  }

  private shouldSignIn(): boolean {
    return this.definition.primaryActionUrl === '/dashboard' && !this.authService.isAuthenticated();
  }

  private primaryActionUrl(): string {
    return this.shouldSignIn() ? '/login' : this.definition.primaryActionUrl;
  }
}

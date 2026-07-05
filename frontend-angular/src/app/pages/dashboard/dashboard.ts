// Simple authenticated landing page that shows the current session and sign-out action.
import { CommonModule } from '@angular/common';
import { Component, inject } from '@angular/core';
import { Router } from '@angular/router';

import { AuthService } from '../../services/auth/auth';

@Component({
  selector: 'app-dashboard-page',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './dashboard.html',
  styleUrl: './dashboard.css',
})
export class DashboardPage {
  private readonly authService = inject(AuthService);
  private readonly router = inject(Router);

  // Returns the email address from the stored authenticated session.
  get userEmail(): string {
    return this.authService.getSession()?.user.email ?? '';
  }

  // Signs the user out by clearing the saved session and returning to login.
  async signOut(): Promise<void> {
    this.authService.logout();
    await this.router.navigateByUrl('/login');
  }
}

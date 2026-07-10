// Simple authenticated landing page that shows the current session and sign-out action.
import { CommonModule } from '@angular/common';
import { Component, inject } from '@angular/core';

import { TopMenuComponent } from '../../components/top-menu/top-menu';
import { AuthService } from '../../services/auth/auth';

@Component({
  selector: 'app-dashboard-page',
  standalone: true,
  imports: [CommonModule, TopMenuComponent],
  templateUrl: './dashboard.html',
  styleUrl: './dashboard.css',
})
export class DashboardPage {
  private readonly authService = inject(AuthService);
  readonly session = this.authService.session;

  // Returns the email address from the stored authenticated session.
  get userEmail(): string {
    return this.authService.getSession()?.user.email ?? '';
  }
}

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

  // Returns the username from the stored authenticated session.
  get username(): string {
    const user = this.authService.getSession()?.user;
    return user?.username || user?.email || '';
  }
}

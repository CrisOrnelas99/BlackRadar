// Read-only authenticated profile information.
import { Component, inject } from '@angular/core';

import { TopMenuComponent } from '../../components/top-menu/top-menu';
import { AuthService } from '../../services/auth/auth';

@Component({
  selector: 'app-profile-page',
  standalone: true,
  imports: [TopMenuComponent],
  templateUrl: './profile.html',
  styleUrl: './profile.css',
})
export class ProfilePage {
  private readonly authService = inject(AuthService);

  readonly session = this.authService.session;
}

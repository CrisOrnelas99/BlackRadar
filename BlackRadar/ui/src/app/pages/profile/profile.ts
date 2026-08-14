import { Component, inject, signal } from '@angular/core';
import { NonNullableFormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';

import { ConfirmationDialogComponent } from '../../components/confirmation-dialog/confirmation-dialog';
import { TopMenuComponent } from '../../components/top-menu/top-menu';
import { AuthService } from '../../services/auth/auth';
import { BannerService } from '../../services/banner/banner';

@Component({
  selector: 'app-profile-page',
  standalone: true,
  imports: [ConfirmationDialogComponent, ReactiveFormsModule, TopMenuComponent],
  templateUrl: './profile.html',
  styleUrl: './profile.css',
})
export class ProfilePage {
  private readonly authService = inject(AuthService);
  private readonly bannerService = inject(BannerService);

  readonly session = this.authService.session;
  readonly isEditing = signal(false);
  readonly isSaving = signal(false);
  readonly isSaveConfirmationOpen = signal(false);
  readonly editForm = inject(NonNullableFormBuilder).group({
    fullName: ['', [Validators.required, Validators.maxLength(100)]],
    username: ['', [Validators.required, Validators.minLength(3), Validators.maxLength(50)]],
    email: ['', [Validators.required, Validators.email]],
  });

  openEditor(): void {
    const currentSession = this.session();
    if (currentSession === null) {
      return;
    }

    this.editForm.reset(currentSession.user);
    this.bannerService.clear();
    this.isEditing.set(true);
  }

  closeEditor(): void {
    if (!this.isSaving()) {
      this.isEditing.set(false);
    }
  }

  saveProfile(): void {
    if (this.isSaving()) {
      return;
    }

    this.bannerService.clear();
    if (this.editForm.invalid) {
      this.editForm.markAllAsTouched();
      this.bannerService.show('Complete all required fields.', 'validation');
      return;
    }

    this.isSaveConfirmationOpen.set(true);
  }

  cancelSave(): void {
    if (!this.isSaving()) {
      this.isSaveConfirmationOpen.set(false);
    }
  }

  confirmSave(): void {
    if (this.isSaving()) {
      return;
    }

    this.isSaveConfirmationOpen.set(false);
    this.isSaving.set(true);
    const formValue = this.editForm.getRawValue();

    this.authService
      .updateProfile({
        fullName: formValue.fullName.trim(),
        username: formValue.username.trim(),
        email: formValue.email.trim(),
      })
      .subscribe({
        next: (user) => {
          this.editForm.reset(user);
          this.isSaving.set(false);
          this.isEditing.set(false);
          this.bannerService.show('Profile updated successfully.', 'success');
        },
        error: () => {
          this.isSaving.set(false);
          this.bannerService.show('Unable to update profile. Try again.', 'validation');
        },
      });
  }
}

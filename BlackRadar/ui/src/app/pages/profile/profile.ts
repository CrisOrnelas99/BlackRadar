import { DatePipe } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { NonNullableFormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { forkJoin } from 'rxjs';

import { ConfirmationDialogComponent } from '../../components/confirmation-dialog/confirmation-dialog';
import { TopMenuComponent } from '../../components/top-menu/top-menu';
import { AuthService } from '../../services/auth/auth';
import { BannerService } from '../../services/banner/banner';
import { ManagedUser, UserAccountStatus, UserRole, UsersService } from '../../services/users/users';

@Component({
  selector: 'app-profile-page',
  standalone: true,
  imports: [
    ConfirmationDialogComponent,
    DatePipe,
    ReactiveFormsModule,
    RouterLink,
    TopMenuComponent,
  ],
  templateUrl: './profile.html',
  styleUrl: './profile.css',
})
export class ProfilePage {
  private readonly authService = inject(AuthService);
  private readonly activatedRoute = inject(ActivatedRoute);
  private readonly bannerService = inject(BannerService);
  private readonly usersService = inject(UsersService);

  readonly session = this.authService.session;
  readonly viewedUser = signal<ManagedUser | null>(null);
  readonly profileUser = computed(() => this.viewedUser() ?? this.session()?.user ?? null);
  readonly isViewingUser = computed(() => this.viewedUser() !== null);
  readonly canEditViewedUser = computed(() => {
    const user = this.viewedUser();
    const currentUser = this.session()?.user;
    return (
      user?.role === 'user' ||
      (currentUser?.role === 'master' && user?.role === 'admin' && user?.id !== currentUser.id)
    );
  });
  readonly hasViewedUserError = signal(false);
  readonly editUserForm = inject(NonNullableFormBuilder).group({
    role: ['user' as UserRole],
    accountStatus: ['active' as UserAccountStatus],
  });
  readonly isEditing = signal(false);
  readonly isSaving = signal(false);
  readonly isSaveConfirmationOpen = signal(false);
  readonly editForm = inject(NonNullableFormBuilder).group({
    fullName: ['', [Validators.required, Validators.maxLength(100)]],
    username: ['', [Validators.required, Validators.minLength(3), Validators.maxLength(50)]],
    email: ['', [Validators.required, Validators.email]],
  });

  constructor() {
    const userId = this.activatedRoute.snapshot.paramMap.get('id');
    if (userId) {
      this.usersService.getUser(userId).subscribe({
        next: (user) => {
          this.viewedUser.set(user);
          this.editUserForm.reset({ role: user.role, accountStatus: user.accountStatus });
        },
        error: () => this.hasViewedUserError.set(true),
      });
    }
  }

  roleLabel(role: string | undefined): string {
    if (role === 'master') return 'System administrator';
    return role === 'admin' ? 'Administrator' : 'User';
  }

  permissionLabel(permission: string): string {
    const labels: Record<string, string> = {
      view_dashboard: 'View the dashboard',
      manage_own_assets: 'View and manage owned assets',
      view_own_vulnerabilities: 'View owned vulnerability data',
      manage_users: 'Manage user accounts',
      manage_administrators: 'Manage administrator accounts',
      manage_vulnerabilities: 'Manage vulnerability records',
      manage_relationships: 'Manage asset and vulnerability relationships',
      approve_cpe_matching: 'Approve CPE matching',
      view_system_health: 'View system health',
    };
    return labels[permission] ?? permission;
  }

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
    if (this.isViewingUser()) {
      this.isSaveConfirmationOpen.set(true);
      return;
    }
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
    if (this.isViewingUser()) {
      this.saveViewedUserChanges();
      return;
    }
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

  openUserEditor(): void {
    const user = this.viewedUser();
    if (!user) return;
    this.editUserForm.reset({ role: user.role, accountStatus: user.accountStatus });
    this.bannerService.clear();
    this.isEditing.set(true);
  }

  private saveViewedUserChanges(): void {
    const user = this.viewedUser();
    if (!user) return;

    this.isSaving.set(true);
    forkJoin({
      role: this.usersService.changeRole(user.id, this.editUserForm.controls.role.value),
      status: this.usersService.changeStatus(
        user.id,
        this.editUserForm.controls.accountStatus.value,
      ),
    }).subscribe({
      next: ({ role, status }) => {
        this.viewedUser.set({ ...status, role: role.role });
        this.isSaving.set(false);
        this.isEditing.set(false);
        this.bannerService.show('User account updated successfully.', 'success');
      },
      error: () => {
        this.isSaving.set(false);
        this.bannerService.show('Unable to update user status. Try again.', 'validation');
      },
    });
  }
}

import { CommonModule } from '@angular/common';
import { Component, OnInit, inject, signal } from '@angular/core';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { Subscription } from 'rxjs';

import { ConfirmationDialogComponent } from '../../components/confirmation-dialog/confirmation-dialog';
import { PaginationComponent } from '../../components/pagination/pagination';
import { TopMenuComponent } from '../../components/top-menu/top-menu';
import { BannerService } from '../../services/banner/banner';
import { AuthService } from '../../services/auth/auth';
import {
  CreateUserRequest,
  ManagedUser,
  UserAccountStatus,
  UsersService,
} from '../../services/users/users';

@Component({
  selector: 'app-users-page',
  standalone: true,
  imports: [
    CommonModule,
    ConfirmationDialogComponent,
    PaginationComponent,
    ReactiveFormsModule,
    RouterLink,
    TopMenuComponent,
  ],
  templateUrl: './users.html',
  styleUrl: './users.css',
})
export class UsersPage implements OnInit {
  private readonly authService = inject(AuthService);
  private readonly bannerService = inject(BannerService);
  private readonly formBuilder = inject(FormBuilder);
  private readonly usersService = inject(UsersService);
  private requestSubscription?: Subscription;

  readonly session = this.authService.session;
  readonly users = signal<ManagedUser[]>([]);
  readonly currentPage = signal(1);
  readonly pageSize = signal(6);
  readonly totalCount = signal(0);
  readonly totalPages = signal(0);
  readonly isLoading = signal(false);
  readonly hasLoadError = signal(false);
  readonly isCreating = signal(false);
  readonly isCreateOpen = signal(false);
  readonly isCreateConfirmationOpen = signal(false);

  readonly createForm = this.formBuilder.nonNullable.group({
    fullName: ['', [Validators.required, Validators.maxLength(120)]],
    username: ['', [Validators.required, Validators.maxLength(80)]],
    email: ['', [Validators.required, Validators.email, Validators.maxLength(254)]],
    password: ['', [Validators.required, Validators.minLength(12)]],
  });

  ngOnInit(): void {
    this.loadUsers();
  }

  loadUsers(): void {
    this.requestSubscription?.unsubscribe();
    this.isLoading.set(true);
    this.hasLoadError.set(false);
    this.requestSubscription = this.usersService.getUsers(this.currentPage()).subscribe({
      next: (response) => {
        if (response.users.length === 0 && response.pagination.page > 1) {
          this.currentPage.set(Math.max(1, response.pagination.totalPages));
          this.loadUsers();
          return;
        }
        this.users.set(response.users);
        this.pageSize.set(response.pagination.pageSize);
        this.totalCount.set(response.pagination.totalCount);
        this.totalPages.set(response.pagination.totalPages);
        this.isLoading.set(false);
      },
      error: () => {
        this.isLoading.set(false);
        this.hasLoadError.set(true);
      },
    });
  }

  changePage(page: number): void {
    this.currentPage.set(page);
    this.loadUsers();
  }

  submitCreate(): void {
    if (this.createForm.invalid || this.isCreating()) {
      this.createForm.markAllAsTouched();
      this.bannerService.show('Complete all required fields.', 'validation');
      return;
    }
    this.isCreateConfirmationOpen.set(true);
  }

  openCreatePanel(): void {
    this.bannerService.clear();
    this.isCreateOpen.set(true);
  }

  closeCreatePanel(): void {
    if (!this.isCreating()) {
      this.createForm.reset();
      this.isCreateOpen.set(false);
    }
  }

  cancelCreate(): void {
    this.isCreateConfirmationOpen.set(false);
  }

  confirmCreate(): void {
    if (this.createForm.invalid || this.isCreating()) return;
    this.isCreating.set(true);
    this.isCreateConfirmationOpen.set(false);
    const request: CreateUserRequest = this.createForm.getRawValue();
    this.usersService.createUser(request).subscribe({
      next: () => {
        this.createForm.reset();
        this.isCreating.set(false);
        this.bannerService.show('User created successfully.', 'success');
        this.currentPage.set(1);
        this.loadUsers();
      },
      error: () => {
        this.isCreating.set(false);
        this.bannerService.show(
          'User could not be created. Check the details and try again.',
          'error',
        );
      },
    });
  }

  roleLabel(role: string): string {
    return role === 'admin' ? 'Administrator' : 'Standard user';
  }

  statusLabel(status: UserAccountStatus): string {
    return status === 'active' ? 'Active' : 'Deactivated';
  }

  statusClass(status: UserAccountStatus): string {
    return status === 'active' ? 'users-status--active' : 'users-status--deactivated';
  }
}

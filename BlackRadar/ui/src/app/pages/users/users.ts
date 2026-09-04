import { CommonModule } from '@angular/common';
import { Component, DestroyRef, OnInit, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { Subscription } from 'rxjs';

import { ConfirmationDialogComponent } from '../../components/confirmation-dialog/confirmation-dialog';
import {
  DataTableCellAction,
  DataTableColumn,
  DataTableComponent,
  DataTableSortChange,
} from '../../components/data-table/data-table';
import { PaginationComponent } from '../../components/pagination/pagination';
import { PageLayoutComponent } from '../../components/page-layout/page-layout';
import { TableToolbarComponent } from '../../components/table-toolbar/table-toolbar';
import { TopMenuComponent } from '../../components/top-menu/top-menu';
import { BannerService } from '../../services/banner/banner';
import { AuthService } from '../../services/auth/auth';
import {
  CreateUserRequest,
  ManagedUser,
  SortDirection,
  UserAccountStatus,
  UserRole,
  UserSortField,
  UsersService,
} from '../../services/users/users';

@Component({
  selector: 'app-users-page',
  standalone: true,
  imports: [
    CommonModule,
    ConfirmationDialogComponent,
    DataTableComponent,
    PaginationComponent,
    PageLayoutComponent,
    ReactiveFormsModule,
    TableToolbarComponent,
    TopMenuComponent,
  ],
  templateUrl: './users.html',
  styleUrl: './users.css',
})
export class UsersPage implements OnInit {
  private readonly authService = inject(AuthService);
  private readonly bannerService = inject(BannerService);
  private readonly formBuilder = inject(FormBuilder);
  private readonly router = inject(Router);
  private readonly destroyRef = inject(DestroyRef);
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
  readonly searchQuery = signal('');
  readonly isFiltersOpen = signal(false);
  readonly sortField = signal<UserSortField>('name');
  readonly sortDirection = signal<SortDirection>('asc');
  readonly isCreating = signal(false);
  readonly isCreateOpen = signal(false);
  readonly isCreateConfirmationOpen = signal(false);

  readonly createForm = this.formBuilder.nonNullable.group({
    fullName: ['', [Validators.required, Validators.maxLength(120)]],
    username: ['', [Validators.required, Validators.maxLength(80)]],
    email: ['', [Validators.required, Validators.email, Validators.maxLength(254)]],
    password: ['', [Validators.required, Validators.minLength(12)]],
  });
  readonly filtersForm = this.formBuilder.nonNullable.group({
    role: ['' as '' | UserRole],
    accountStatus: ['' as '' | UserAccountStatus],
  });
  readonly userRowKey = (user: ManagedUser): string => user.id;
  readonly userColumns: readonly DataTableColumn<ManagedUser>[] = [
    {
      key: 'accountStatus',
      label: 'Status',
      cellValue: (user) => this.statusLabel(user.accountStatus),
      cellType: 'badge',
      cellClass: (user) =>
        user.accountStatus === 'active'
          ? 'data-table-badge--active'
          : 'data-table-badge--deactivated',
      sortable: true,
    },
    {
      key: 'name',
      label: 'Name',
      cellValue: (user) => user.fullName,
      cellType: 'action',
      cellActionEnabled: (user) => this.canOpenUserProfile(user),
      sortable: true,
    },
    {
      key: 'username',
      label: 'Username',
      cellValue: (user) => user.username,
      sortable: true,
    },
    {
      key: 'email',
      label: 'Email',
      cellValue: (user) => user.email,
      sortable: true,
    },
    {
      key: 'role',
      label: 'Role',
      cellValue: (user) => this.roleLabel(user.role),
      sortable: true,
    },
  ];

  ngOnInit(): void {
    this.filtersForm.valueChanges.pipe(takeUntilDestroyed(this.destroyRef)).subscribe(() => {
      this.currentPage.set(1);
      this.loadUsers();
    });
    this.loadUsers();
  }

  loadUsers(): void {
    this.requestSubscription?.unsubscribe();
    this.isLoading.set(true);
    this.hasLoadError.set(false);
    const filters = this.filtersForm.getRawValue();
    this.requestSubscription = this.usersService
      .getUsers({
        page: this.currentPage(),
        search: this.searchQuery(),
        role: filters.role || undefined,
        accountStatus: filters.accountStatus || undefined,
        sortField: this.sortField(),
        sortDirection: this.sortDirection(),
      })
      .subscribe({
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

  updateSearchQuery(query: string): void {
    this.searchQuery.set(query);
    this.currentPage.set(1);
    this.loadUsers();
  }

  toggleFilters(): void {
    this.isFiltersOpen.update((isOpen) => !isOpen);
  }

  clearFilters(): void {
    this.searchQuery.set('');
    this.isFiltersOpen.set(false);
    this.sortField.set('name');
    this.sortDirection.set('asc');
    this.filtersForm.reset({ role: '', accountStatus: '' }, { emitEvent: false });
    this.currentPage.set(1);
    this.loadUsers();
  }

  handleSortChange(change: DataTableSortChange): void {
    if (!this.isUserSortField(change.field)) {
      return;
    }

    this.sortField.set(change.field);
    this.sortDirection.set(change.direction);
    this.currentPage.set(1);
    this.loadUsers();
  }

  async handleTableAction(action: DataTableCellAction<ManagedUser>): Promise<void> {
    if (action.column.key !== 'name' || !this.canOpenUserProfile(action.row)) {
      return;
    }

    await this.router.navigate(
      action.row.id === this.session()?.user?.id ? ['/profile'] : ['/profile', action.row.id],
    );
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
    if (role === 'master') return 'System administrator';
    return role === 'admin' ? 'Administrator' : 'Standard user';
  }

  canOpenUserProfile(user: ManagedUser): boolean {
    return user.role !== 'master' || this.session()?.user.role === 'master';
  }

  statusLabel(status: UserAccountStatus): string {
    return status === 'active' ? 'Active' : 'Deactivated';
  }

  private isUserSortField(value: string): value is UserSortField {
    return (
      value === 'name' ||
      value === 'username' ||
      value === 'email' ||
      value === 'role' ||
      value === 'accountStatus'
    );
  }
}

// Authenticated page that lists the vulnerabilities visible to the current user.
import { Component, computed, ElementRef, inject, signal, ViewChild } from '@angular/core';
import { Router } from '@angular/router';
import { toSignal } from '@angular/core/rxjs-interop';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { startWith } from 'rxjs';

import {
  DataTableCellAction,
  DataTableColumn,
  DataTableComponent,
} from '../../components/data-table/data-table';
import { ConfirmationDialogComponent } from '../../components/confirmation-dialog/confirmation-dialog';
import { TableToolbarComponent } from '../../components/table-toolbar/table-toolbar';
import { TopMenuComponent } from '../../components/top-menu/top-menu';
import { AuthService } from '../../services/auth/auth';
import {
  CreateVulnerabilityRequest,
  Vulnerability,
  VulnerabilitiesService,
} from '../../services/vulnerabilities/vulnerabilities';
import { BannerService } from '../../services/banner/banner';
import { semanticLevelClass } from '../../utils/semantic-level';

type VulnerabilitySortField = 'cveId' | 'title' | 'severity' | 'status' | 'affectedAssetCount';
type SortDirection = 'asc' | 'desc';

@Component({
  selector: 'app-vulnerabilities-page',
  standalone: true,
  imports: [
    ConfirmationDialogComponent,
    DataTableComponent,
    ReactiveFormsModule,
    TableToolbarComponent,
    TopMenuComponent,
  ],
  templateUrl: './vulnerabilities.html',
  styleUrl: './vulnerabilities.css',
})
export class VulnerabilitiesPage {
  private readonly authService = inject(AuthService);
  private readonly bannerService = inject(BannerService);
  private readonly formBuilder = inject(FormBuilder);
  private readonly router = inject(Router);
  private readonly vulnerabilitiesService = inject(VulnerabilitiesService);

  readonly session = this.authService.session;
  readonly vulnerabilities = signal<Vulnerability[]>([]);
  readonly isLoading = signal(true);
  readonly hasLoadError = signal(false);
  readonly isDeleting = signal(false);
  readonly vulnerabilityPendingDeletion = signal<Vulnerability | null>(null);
  readonly searchQuery = signal('');
  readonly isFiltersOpen = signal(false);
  readonly isSortOpen = signal(false);
  readonly isCreating = signal(false);
  readonly isCreateConfirmationOpen = signal(false);
  readonly isCreateOpen = signal(false);
  readonly createForm = this.formBuilder.nonNullable.group({
    cveId: ['', Validators.pattern(/^CVE-\d{4}-\d{4,}$/i)],
    title: ['', [Validators.required, Validators.maxLength(300)]],
    severity: ['Medium', Validators.required],
    description: ['', [Validators.required, Validators.maxLength(5000)]],
    status: ['Open', Validators.required],
  });
  readonly severityOptions = ['Low', 'Medium', 'High', 'Critical'];
  readonly statusOptions = ['Open', 'In Progress', 'Fixed'];
  readonly filtersForm = this.formBuilder.nonNullable.group({
    severity: [''],
    status: [''],
    sortField: ['title' as VulnerabilitySortField],
    sortDirection: ['asc' as SortDirection],
  });

  @ViewChild('createTrigger') private createTrigger?: ElementRef<HTMLButtonElement>;
  @ViewChild('firstCreateControl') private firstCreateControl?: ElementRef<HTMLInputElement>;

  openCreatePanel(): void {
    this.isCreateOpen.set(true);
    setTimeout(() => this.firstCreateControl?.nativeElement.focus());
  }

  closeCreatePanel(): void {
    if (!this.isCreating()) {
      this.isCreateOpen.set(false);
      setTimeout(() => this.createTrigger?.nativeElement.focus());
    }
  }
  readonly filtersFormValue = toSignal(
    this.filtersForm.valueChanges.pipe(startWith(this.filtersForm.getRawValue())),
    { initialValue: this.filtersForm.getRawValue() },
  );
  readonly filteredVulnerabilities = computed(() => {
    const query = this.searchQuery().trim().toLocaleLowerCase();
    const formValue = this.filtersFormValue();
    const severity = this.coerceFilterText(formValue.severity);
    const status = this.coerceFilterText(formValue.status);
    const sortField = this.coerceSortField(formValue.sortField);
    const sortDirection = this.coerceSortDirection(formValue.sortDirection);
    const filtered = this.vulnerabilities().filter((vulnerability) => {
      const searchableText = `${vulnerability.cveId} ${vulnerability.title}`.toLocaleLowerCase();
      return (
        (query === '' || searchableText.includes(query)) &&
        (severity === '' || vulnerability.severity === severity) &&
        (status === '' || vulnerability.status === status)
      );
    });

    return [...filtered].sort((left, right) => {
      const comparison = this.compareVulnerabilities(left, right, sortField);
      return sortDirection === 'asc' ? comparison : comparison * -1;
    });
  });
  readonly vulnerabilityColumns: readonly DataTableColumn<Vulnerability>[] = [
    {
      key: 'status',
      label: 'Status',
      cellValue: (vulnerability) => vulnerability.status,
    },
    {
      key: 'title',
      label: 'Title',
      cellValue: (vulnerability) => vulnerability.title,
      cellType: 'link',
      cellLink: (vulnerability) => ['/vulnerabilities', vulnerability.id],
      width: '55%',
    },
    {
      key: 'severity',
      label: 'Severity',
      cellValue: (vulnerability) => vulnerability.severity,
      cellClass: (vulnerability) => semanticLevelClass(vulnerability.severity),
    },
    {
      key: 'cveId',
      label: 'CVE ID',
      cellValue: (vulnerability) => vulnerability.cveId || '—',
    },
    {
      key: 'affectedAssetCount',
      label: 'Affected assets',
      cellValue: (vulnerability) =>
        vulnerability.affectedAssetCount === undefined
          ? '—'
          : String(vulnerability.affectedAssetCount),
      cellType: 'action',
    },
    {
      key: 'delete',
      label: '',
      cellValue: () => '',
      cellType: 'delete',
      deleteLabel: 'Delete vulnerability',
      width: '3.5rem',
    },
  ];
  readonly vulnerabilityRowKey = (vulnerability: Vulnerability): string => vulnerability.id;

  constructor() {
    this.loadVulnerabilities();
  }

  updateSearchQuery(query: string): void {
    this.searchQuery.set(query);
  }

  toggleSort(): void {
    this.isSortOpen.update((isOpen) => !isOpen);
  }

  toggleFilters(): void {
    this.isFiltersOpen.update((isOpen) => !isOpen);
  }

  clearFilters(): void {
    this.searchQuery.set('');
    this.isFiltersOpen.set(false);
    this.isSortOpen.set(false);
    this.filtersForm.reset({
      severity: '',
      status: '',
      sortField: 'title',
      sortDirection: 'asc',
    });
  }

  createVulnerability(): void {
    this.bannerService.clear();

    if (this.createForm.invalid) {
      this.createForm.markAllAsTouched();
      this.bannerService.show('Complete all required fields.', 'validation');
      return;
    }

    this.isCreateConfirmationOpen.set(true);
  }

  cancelCreate(): void {
    if (!this.isCreating()) {
      this.isCreateConfirmationOpen.set(false);
    }
  }

  confirmCreate(): void {
    if (this.isCreating() || this.createForm.invalid) {
      return;
    }

    this.isCreateConfirmationOpen.set(false);
    this.isCreating.set(true);
    const formValue = this.createForm.getRawValue();
    const request: CreateVulnerabilityRequest = {
      cveId: formValue.cveId.trim().toUpperCase(),
      title: formValue.title.trim(),
      severity: formValue.severity,
      description: formValue.description.trim(),
      status: formValue.status,
    };

    this.vulnerabilitiesService.createVulnerability(request).subscribe({
      next: (vulnerability) => {
        this.vulnerabilities.update((vulnerabilities) => [...vulnerabilities, vulnerability]);
        this.createForm.reset({
          cveId: '',
          title: '',
          severity: 'Medium',
          description: '',
          status: 'Open',
        });
        this.isCreating.set(false);
        this.isCreateOpen.set(false);
        this.bannerService.show('Vulnerability created successfully.', 'success');
      },
      error: () => {
        this.isCreating.set(false);
        this.bannerService.show('Unable to create vulnerability. Try again.', 'validation');
      },
    });
  }

  async handleTableAction(action: DataTableCellAction<Vulnerability>): Promise<void> {
    if (action.column.key === 'affectedAssetCount') {
      await this.router.navigate(['/vulnerabilities', action.row.id, 'assets']);
      return;
    }

    if (action.column.key === 'delete') {
      this.vulnerabilityPendingDeletion.set(action.row);
    }
  }

  cancelVulnerabilityDeletion(): void {
    if (!this.isDeleting()) {
      this.vulnerabilityPendingDeletion.set(null);
    }
  }

  confirmVulnerabilityDeletion(): void {
    const vulnerability = this.vulnerabilityPendingDeletion();
    if (vulnerability === null || this.isDeleting()) {
      return;
    }

    this.isDeleting.set(true);
    this.vulnerabilitiesService.deleteVulnerability(vulnerability.id).subscribe({
      next: () => {
        this.vulnerabilities.update((vulnerabilities) =>
          vulnerabilities.filter((current) => current.id !== vulnerability.id),
        );
        this.vulnerabilityPendingDeletion.set(null);
        this.isDeleting.set(false);
        this.bannerService.show('Vulnerability deleted successfully.', 'success');
      },
      error: () => {
        this.isDeleting.set(false);
        this.bannerService.show('Unable to delete vulnerability. Try again.', 'validation');
      },
    });
  }

  private loadVulnerabilities(): void {
    this.vulnerabilitiesService.getVulnerabilities().subscribe({
      next: (vulnerabilities) => {
        this.vulnerabilities.set(vulnerabilities);
        this.isLoading.set(false);
      },
      error: () => {
        this.hasLoadError.set(true);
        this.isLoading.set(false);
      },
    });
  }

  private compareVulnerabilities(
    left: Vulnerability,
    right: Vulnerability,
    sortField: VulnerabilitySortField,
  ): number {
    if (sortField === 'affectedAssetCount') {
      return left.affectedAssetCount - right.affectedAssetCount;
    }

    return String(left[sortField]).localeCompare(String(right[sortField]), undefined, {
      numeric: true,
      sensitivity: 'base',
    });
  }

  private coerceFilterText(value: unknown): string {
    return typeof value === 'string' ? value : '';
  }

  private coerceSortField(value: unknown): VulnerabilitySortField {
    if (
      value === 'cveId' ||
      value === 'title' ||
      value === 'severity' ||
      value === 'status' ||
      value === 'affectedAssetCount'
    ) {
      return value;
    }

    return 'title';
  }

  private coerceSortDirection(value: unknown): SortDirection {
    return value === 'desc' ? 'desc' : 'asc';
  }
}

import { Component, computed, input, output } from '@angular/core';

// Reusable accessible controls for navigating a bounded data-table result set.
@Component({
  selector: 'app-pagination',
  standalone: true,
  templateUrl: './pagination.html',
  styleUrl: './pagination.css',
})
export class PaginationComponent {
  readonly page = input.required<number>();
  readonly pageSize = input.required<number>();
  readonly totalCount = input.required<number>();
  readonly totalPages = input.required<number>();
  readonly pageChange = output<number>();
  readonly displayTotalPages = computed(() => Math.max(1, this.totalPages()));
  readonly summary = computed(() => {
    if (this.totalCount() === 0) return 'No results';
    const first = (this.page() - 1) * this.pageSize() + 1;
    const last = Math.min(this.page() * this.pageSize(), this.totalCount());
    return `Showing ${first}-${last} of ${this.totalCount()}`;
  });

  selectPage(page: number): void {
    if (page >= 1 && page <= this.displayTotalPages() && page !== this.page()) {
      this.pageChange.emit(page);
    }
  }
}

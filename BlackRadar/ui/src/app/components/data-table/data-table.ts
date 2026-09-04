// Reusable typed table component that renders configurable columns and rows.
import { Component, input, output } from '@angular/core';
import { RouterLink } from '@angular/router';

export interface DataTableColumn<TRow> {
  key: string;
  label: string;
  cellValue: (row: TRow) => string;
  cellType?: 'text' | 'action' | 'link' | 'badge' | 'delete' | 'unlink';
  cellActionEnabled?: (row: TRow) => boolean;
  cellLink?: (row: TRow) => readonly (string | number)[];
  cellClass?: (row: TRow) => string;
  deleteLabel?: string;
  sortable?: boolean;
  width?: string;
}

export type DataTableSortDirection = 'asc' | 'desc';

export interface DataTableSortChange {
  field: string;
  direction: DataTableSortDirection;
}

export interface DataTableCellAction<TRow> {
  column: DataTableColumn<TRow>;
  row: TRow;
}

@Component({
  selector: 'app-data-table',
  standalone: true,
  imports: [RouterLink],
  templateUrl: './data-table.html',
  styleUrl: './data-table.css',
})
export class DataTableComponent<TRow> {
  readonly columns = input.required<readonly DataTableColumn<TRow>[]>();
  readonly rows = input.required<readonly TRow[]>();
  readonly rowKey = input<((row: TRow) => string | number) | null>(null);
  readonly sortField = input<string | null>(null);
  readonly sortDirection = input<DataTableSortDirection>('asc');
  readonly cellAction = output<DataTableCellAction<TRow>>();
  readonly sortChange = output<DataTableSortChange>();

  // Emits the row and column when an action cell is selected.
  emitCellAction(column: DataTableColumn<TRow>, row: TRow): void {
    this.cellAction.emit({ column, row });
  }

  emitSortChange(column: DataTableColumn<TRow>): void {
    if (!column.sortable) {
      return;
    }

    const direction =
      this.sortField() === column.key && this.sortDirection() === 'asc' ? 'desc' : 'asc';
    this.sortChange.emit({ field: column.key, direction });
  }

  sortLabel(column: DataTableColumn<TRow>): string {
    if (this.sortField() !== column.key) {
      return `Sort by ${column.label}`;
    }

    return `Sort by ${column.label} ${this.sortDirection() === 'asc' ? 'descending' : 'ascending'}`;
  }

  trackRow(_index: number, row: TRow): string | number {
    const rowKey = this.rowKey();
    return rowKey ? rowKey(row) : _index;
  }
}

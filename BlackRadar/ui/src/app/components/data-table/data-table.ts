// Reusable typed table component that renders configurable columns and rows.
import { Component, input, output } from '@angular/core';

export interface DataTableColumn<TRow> {
  key: string;
  label: string;
  cellValue: (row: TRow) => string;
  cellType?: 'text' | 'action' | 'delete';
  width?: string;
}

export interface DataTableCellAction<TRow> {
  column: DataTableColumn<TRow>;
  row: TRow;
}

@Component({
  selector: 'app-data-table',
  standalone: true,
  templateUrl: './data-table.html',
  styleUrl: './data-table.css',
})
export class DataTableComponent<TRow> {
  readonly columns = input.required<readonly DataTableColumn<TRow>[]>();
  readonly rows = input.required<readonly TRow[]>();
  readonly cellAction = output<DataTableCellAction<TRow>>();

  // Emits the row and column when an action cell is selected.
  emitCellAction(column: DataTableColumn<TRow>, row: TRow): void {
    this.cellAction.emit({ column, row });
  }
}

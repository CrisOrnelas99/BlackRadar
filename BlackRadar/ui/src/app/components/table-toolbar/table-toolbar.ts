import { Component, input, output } from '@angular/core';

@Component({
  selector: 'app-table-toolbar',
  standalone: true,
  templateUrl: './table-toolbar.html',
  styleUrl: './table-toolbar.css',
})
export class TableToolbarComponent {
  readonly searchLabel = input.required<string>();
  readonly searchId = input.required<string>();
  readonly searchPlaceholder = input.required<string>();
  readonly searchValue = input.required<string>();

  readonly searchChange = output<string>();
}

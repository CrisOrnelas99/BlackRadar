import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';

import { DataTableColumn, DataTableComponent } from './data-table';

interface TestRow {
  id: string;
  name: string;
}

describe('DataTableComponent', () => {
  let fixture: ComponentFixture<DataTableComponent<TestRow>>;
  let component: DataTableComponent<TestRow>;
  const rows: readonly TestRow[] = [{ id: 'asset-1', name: 'Primary server' }];
  const columns: readonly DataTableColumn<TestRow>[] = [
    {
      key: 'name',
      label: 'Name',
      cellValue: (row) => row.name,
      cellType: 'action',
    },
  ];

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [DataTableComponent<TestRow>],
      providers: [provideRouter([])],
    }).compileComponents();

    fixture = TestBed.createComponent(DataTableComponent<TestRow>);
    component = fixture.componentInstance;
    fixture.componentRef.setInput('columns', columns);
    fixture.componentRef.setInput('rows', rows);
    fixture.detectChanges();
  });

  it('emits the selected row and column when an action cell is clicked', () => {
    const emitSpy = vi.spyOn(component.cellAction, 'emit');
    const actionButton = fixture.nativeElement.querySelector(
      '.data-table-action',
    ) as HTMLButtonElement;

    actionButton.click();

    expect(emitSpy).toHaveBeenCalledWith({ column: columns[0], row: rows[0] });
  });

  it('tracks rows with the supplied row key and falls back to the row index', () => {
    fixture.componentRef.setInput('rowKey', (row: TestRow) => row.id);
    fixture.detectChanges();

    expect(component.trackRow(4, rows[0])).toBe('asset-1');

    fixture.componentRef.setInput('rowKey', null);
    fixture.detectChanges();

    expect(component.trackRow(4, rows[0])).toBe(4);
  });

  it('renders a configured link cell with its row route', () => {
    const linkColumn: DataTableColumn<TestRow> = {
      key: 'details',
      label: 'Details',
      cellValue: (row) => row.name,
      cellType: 'link',
      cellLink: (row) => ['/assets', row.id],
    };
    fixture.componentRef.setInput('columns', [linkColumn]);
    fixture.detectChanges();

    const link = fixture.nativeElement.querySelector('a') as HTMLAnchorElement;
    expect(link.textContent.trim()).toBe('Primary server');
    expect(link.getAttribute('href')).toBe('/assets/asset-1');
  });

  it('emits ascending and descending changes from sortable header arrows', () => {
    const sortableColumn: DataTableColumn<TestRow> = {
      key: 'name',
      label: 'Name',
      cellValue: (row) => row.name,
      sortable: true,
    };
    const sortSpy = vi.spyOn(component.sortChange, 'emit');
    fixture.componentRef.setInput('columns', [sortableColumn]);
    fixture.componentRef.setInput('sortField', 'name');
    fixture.componentRef.setInput('sortDirection', 'asc');
    fixture.detectChanges();

    const sortButton = fixture.nativeElement.querySelector(
      '.data-table-sort-button',
    ) as HTMLButtonElement;
    sortButton.click();

    expect(sortSpy).toHaveBeenCalledWith({ field: 'name', direction: 'desc' });
  });
});

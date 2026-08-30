import { ComponentFixture, TestBed } from '@angular/core/testing';

import { PaginationComponent } from './pagination';

describe('PaginationComponent', () => {
  let fixture: ComponentFixture<PaginationComponent>;
  let component: PaginationComponent;

  beforeEach(async () => {
    await TestBed.configureTestingModule({ imports: [PaginationComponent] }).compileComponents();
    fixture = TestBed.createComponent(PaginationComponent);
    component = fixture.componentInstance;
    fixture.componentRef.setInput('page', 1);
    fixture.componentRef.setInput('pageSize', 6);
    fixture.componentRef.setInput('totalCount', 10);
    fixture.componentRef.setInput('totalPages', 2);
    fixture.detectChanges();
  });

  it('renders accessible next-page controls and emits the selected page', () => {
    const emitSpy = vi.spyOn(component.pageChange, 'emit');
    const nextButton = fixture.nativeElement.querySelectorAll('button')[1] as HTMLButtonElement;

    expect(fixture.nativeElement.querySelector('nav')?.getAttribute('aria-label')).toBe(
      'Table pagination',
    );
    expect(nextButton.disabled).toBe(false);
    nextButton.click();

    expect(emitSpy).toHaveBeenCalledWith(2);
  });

  it('renders disabled controls for a single page', () => {
    fixture.componentRef.setInput('totalCount', 1);
    fixture.componentRef.setInput('totalPages', 1);
    fixture.detectChanges();

    const buttons = fixture.nativeElement.querySelectorAll(
      'button',
    ) as NodeListOf<HTMLButtonElement>;
    expect(fixture.nativeElement.querySelector('nav')).not.toBeNull();
    expect(buttons[0].disabled).toBe(true);
    expect(buttons[1].disabled).toBe(true);
  });
});

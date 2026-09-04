import { Component } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';

import { PageLayoutComponent } from './page-layout';

@Component({
  standalone: true,
  imports: [PageLayoutComponent],
  template: `
    <app-page-layout [backLabel]="'Back to list'" [backLink]="'/items'">
      <h1 page-layout-heading>Items</h1>
      <div page-layout-toolbar>Toolbar</div>
      <section page-layout-main>Main content</section>
      <aside page-layout-side>Side content</aside>
      <div page-layout-pagination>Pagination</div>
    </app-page-layout>
  `,
})
class TestHostComponent {}

describe('PageLayoutComponent', () => {
  let fixture: ComponentFixture<TestHostComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [TestHostComponent],
      providers: [provideRouter([])],
    }).compileComponents();
    fixture = TestBed.createComponent(TestHostComponent);
    fixture.detectChanges();
  });

  it('projects page regions into the shared layout', () => {
    const layout = fixture.nativeElement.querySelector('app-page-layout');

    expect(layout.querySelector('.page-layout-header h1')?.textContent).toContain('Items');
    expect(
      layout.querySelector('.page-layout-header [page-layout-toolbar]')?.textContent,
    ).toContain('Toolbar');
    expect(layout.querySelector('.page-layout-main [page-layout-main]')?.textContent).toContain(
      'Main content',
    );
    expect(layout.querySelector('.page-layout-side [page-layout-side]')?.textContent).toContain(
      'Side content',
    );
    expect(
      layout.querySelector('.page-layout-pagination [page-layout-pagination]')?.textContent,
    ).toContain('Pagination');
    expect(layout.querySelector('.page-back-link')?.textContent).toContain('Back to list');
  });
});

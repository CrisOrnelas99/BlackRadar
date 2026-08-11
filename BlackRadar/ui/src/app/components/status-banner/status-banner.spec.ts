import { ComponentFixture, TestBed } from '@angular/core/testing';

import { StatusBannerComponent } from './status-banner';

describe('StatusBannerComponent', () => {
  let fixture: ComponentFixture<StatusBannerComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [StatusBannerComponent],
    }).compileComponents();

    fixture = TestBed.createComponent(StatusBannerComponent);
    fixture.componentRef.setInput('message', 'Asset updated successfully.');
    fixture.componentRef.setInput('tone', 'success');
    fixture.detectChanges();
  });

  it('renders the message with the matching tone class', () => {
    const bannerElement = fixture.nativeElement.querySelector('.status-banner') as HTMLElement;

    expect(bannerElement.textContent).toContain('Asset updated successfully.');
    expect(bannerElement.classList.contains('status-banner--success')).toBe(true);
  });
});

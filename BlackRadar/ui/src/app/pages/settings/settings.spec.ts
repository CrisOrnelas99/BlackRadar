import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { signal } from '@angular/core';

import { AuthService, LoginResponse } from '../../services/auth/auth';
import { SettingsPage } from './settings';

describe('SettingsPage', () => {
  let fixture: ComponentFixture<SettingsPage>;
  let page: SettingsPage;

  const session: LoginResponse = {
    user: {
      id: 'user-1',
      fullName: 'BlackRadar User',
      username: 'blackradar_user',
      email: 'user@example.invalid',
    },
    token: 'token',
    tokenExpiresAt: '2026-08-11T12:00:00Z',
    refreshTokenExpiresAt: '2026-08-12T12:00:00Z',
  };

  beforeEach(async () => {
    window.localStorage.removeItem('blackradar-theme');
    document.documentElement.classList.remove('blackradar-dark-theme');

    await TestBed.configureTestingModule({
      imports: [SettingsPage],
      providers: [
        provideRouter([]),
        { provide: AuthService, useValue: { session: signal(session) } },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(SettingsPage);
    page = fixture.componentInstance;
    fixture.detectChanges();
  });

  afterEach(() => {
    window.localStorage.removeItem('blackradar-theme');
    document.documentElement.classList.remove('blackradar-dark-theme');
  });

  it('renders the appearance setting', () => {
    expect(fixture.nativeElement.textContent).toContain('Appearance');
    expect(fixture.nativeElement.textContent).toContain('Dark mode');
  });

  it('applies and persists dark mode from the switch', () => {
    const switchControl = fixture.nativeElement.querySelector(
      'input[role="switch"]',
    ) as HTMLInputElement;
    switchControl.checked = true;

    switchControl.dispatchEvent(new Event('change'));
    fixture.detectChanges();

    expect(page.themeService.theme()).toBe('dark');
    expect(document.documentElement.classList.contains('blackradar-dark-theme')).toBe(true);
    expect(window.localStorage.getItem('blackradar-theme')).toBe('dark');
  });
});

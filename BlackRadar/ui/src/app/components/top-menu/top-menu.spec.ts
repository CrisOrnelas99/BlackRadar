import { ComponentFixture, TestBed } from '@angular/core/testing';
import { signal } from '@angular/core';
import { of, throwError } from 'rxjs';
import { Router } from '@angular/router';

import { TopMenuComponent } from './top-menu';
import { AuthService, LoginResponse } from '../../services/auth/auth';
import { BannerService } from '../../services/banner/banner';

describe('TopMenuComponent', () => {
  let fixture: ComponentFixture<TopMenuComponent>;
  let component: TopMenuComponent;
  let authServiceMock: {
    session: ReturnType<typeof signal<LoginResponse | null>>;
    logout: ReturnType<typeof vi.fn>;
  };
  let bannerServiceMock: { show: ReturnType<typeof vi.fn> };
  let routerMock: { navigateByUrl: ReturnType<typeof vi.fn> };

  const session: LoginResponse = {
    user: {
      id: 'user-1',
      fullName: 'System Admin',
      username: 'system_admin',
      email: 'system_admin@example.invalid',
    },
    token: 'token',
    tokenExpiresAt: '2026-08-11T12:00:00Z',
    refreshTokenExpiresAt: '2026-08-12T12:00:00Z',
  };

  beforeEach(async () => {
    authServiceMock = {
      session: signal(session),
      logout: vi.fn(() => of(void 0)),
    };
    bannerServiceMock = {
      show: vi.fn(),
    };
    routerMock = {
      navigateByUrl: vi.fn(() => Promise.resolve(true)),
    };

    await TestBed.configureTestingModule({
      imports: [TopMenuComponent],
      providers: [
        { provide: AuthService, useValue: authServiceMock },
        { provide: BannerService, useValue: bannerServiceMock },
        { provide: Router, useValue: routerMock },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(TopMenuComponent);
    component = fixture.componentInstance;
    fixture.componentRef.setInput('session', session);
    fixture.componentRef.setInput('currentUrl', '/dashboard');
    fixture.detectChanges();
  });

  it('prefers the full name for the displayed account label', () => {
    expect(component.displayName).toBe('System Admin');
  });

  it('keeps primary navigation visible and account actions in the hamburger menu', () => {
    expect(fixture.nativeElement.querySelector('.top-menu-primary').textContent).toContain(
      'Dashboard',
    );
    expect(fixture.nativeElement.querySelector('.top-menu-primary').textContent).toContain(
      'Assets',
    );
    expect(fixture.nativeElement.querySelector('.top-menu-primary').textContent).toContain(
      'Vulnerabilities',
    );
    expect(fixture.nativeElement.querySelector('.top-menu-dropdown')).toBeNull();

    expect(component.primaryNavigationItems.map((item) => item.label)).toEqual([
      'Dashboard',
      'Assets',
      'Vulnerabilities',
    ]);
    expect(component.accountNavigationItems.map((item) => item.label)).toEqual(['Profile']);
  });

  it('signs the user out and navigates to the login page on success', async () => {
    await component.signOut();

    expect(authServiceMock.logout).toHaveBeenCalledTimes(1);
    expect(bannerServiceMock.show).toHaveBeenCalledWith('Signed out successfully.', 'success');
    expect(routerMock.navigateByUrl).toHaveBeenCalledWith('/login');
  });

  it('shows an error banner when sign out fails', async () => {
    authServiceMock.logout.mockReturnValueOnce(throwError(() => new Error('logout failed')));

    await component.signOut();

    expect(bannerServiceMock.show).toHaveBeenCalledWith(
      'Unable to confirm sign-out. Try again.',
      'error',
    );
  });
});

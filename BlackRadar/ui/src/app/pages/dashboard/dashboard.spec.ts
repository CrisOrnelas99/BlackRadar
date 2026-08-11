import { ComponentFixture, TestBed } from '@angular/core/testing';
import { signal } from '@angular/core';
import { Router } from '@angular/router';

import { DashboardPage } from './dashboard';
import { AuthService, LoginResponse } from '../../services/auth/auth';
import { BannerService } from '../../services/banner/banner';

describe('DashboardPage', () => {
  let fixture: ComponentFixture<DashboardPage>;

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
    await TestBed.configureTestingModule({
      imports: [DashboardPage],
      providers: [
        {
          provide: AuthService,
          useValue: {
            session: signal(session),
            getSession: vi.fn(() => session),
            logout: vi.fn(),
          },
        },
        { provide: BannerService, useValue: { show: vi.fn() } },
        { provide: Router, useValue: { navigateByUrl: vi.fn(() => Promise.resolve(true)) } },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(DashboardPage);
    fixture.detectChanges();
  });

  it('renders the signed-in username', () => {
    const content = fixture.nativeElement as HTMLElement;

    expect(content.textContent).toContain('system_admin');
  });
});

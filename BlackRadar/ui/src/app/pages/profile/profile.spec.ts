import { TestBed } from '@angular/core/testing';
import { signal } from '@angular/core';
import { ActivatedRoute, convertToParamMap } from '@angular/router';
import { of, Subject, throwError } from 'rxjs';
import { ProfilePage } from './profile';
import { AuthService } from '../../services/auth/auth';
import { ManagedUser, UserRole, UsersService } from '../../services/users/users';
import { BannerService } from '../../services/banner/banner';

describe('Profile password reset', () => {
  const session = signal<{ user: { id: string; role: string } } | null>(null);
  const target: ManagedUser = {
    id: 'target',
    role: 'user',
    accountStatus: 'active',
    fullName: 'Test User',
    username: 'test-user',
    email: 'test@example.com',
    createdAt: '2026-09-01T00:00:00Z',
    updatedAt: '2026-09-01T00:00:00Z',
  };
  const resetPassword = vi.fn();
  const show = vi.fn();

  beforeEach(() => {
    session.set({ user: { id: 'actor', role: 'admin' } });
    resetPassword.mockReset();
    show.mockReset();
    TestBed.configureTestingModule({
      providers: [
        { provide: AuthService, useValue: { session } },
        {
          provide: ActivatedRoute,
          useValue: { snapshot: { paramMap: convertToParamMap({ id: 'target' }) } },
        },
        { provide: UsersService, useValue: { getUser: () => of(target), resetPassword } },
        { provide: BannerService, useValue: { show, clear: vi.fn() } },
      ],
    });
  });

  function page(): ProfilePage {
    return TestBed.runInInjectionContext(() => new ProfilePage());
  }

  it.each([
    ['master', 'admin', true],
    ['master', 'master', true],
    ['admin', 'user', true],
    ['admin', 'admin', false],
    ['admin', 'master', false],
    ['user', 'user', false],
  ])('allows %s to reset %s: %s', (actor, role, allowed) => {
    session.set({ user: { id: 'actor', role: actor } });
    const component = page();
    component.viewedUser.set({ ...target, role: role as UserRole });
    component.openPasswordReset();
    expect(component.isPasswordResetOpen()).toBe(allowed);
  });

  it.each([
    ['short', 'short'],
    ['Password1!', 'different'],
    [' Password1!', ' Password1!'],
  ])('rejects invalid or mismatched passwords', (password, confirmPassword) => {
    const component = page();
    component.openPasswordReset();
    component.resetPasswordForm.setValue({ password, confirmPassword });
    component.confirmPasswordReset();
    expect(resetPassword).not.toHaveBeenCalled();
    expect(component.isPasswordResetOpen()).toBe(true);
  });

  it('prevents duplicate submissions and closes both editors after success', () => {
    const response = new Subject<void>();
    resetPassword.mockReturnValue(response);
    const component = page();
    component.openUserEditor();
    component.openPasswordReset();
    component.resetPasswordForm.setValue({ password: 'Password1!', confirmPassword: 'Password1!' });
    component.confirmPasswordReset();
    component.confirmPasswordReset();
    expect(resetPassword).toHaveBeenCalledExactlyOnceWith('target', 'Password1!');
    response.next();
    response.complete();
    expect(component.isPasswordResetOpen()).toBe(false);
    expect(component.isEditing()).toBe(false);
    expect(component.resetPasswordForm.controls.password.value).toBe('');
  });

  it('keeps the dialog open after a failed request', () => {
    resetPassword.mockReturnValue(throwError(() => new Error('unavailable')));
    const component = page();
    component.openPasswordReset();
    component.resetPasswordForm.setValue({ password: 'Password1!', confirmPassword: 'Password1!' });
    component.confirmPasswordReset();
    expect(component.isPasswordResetOpen()).toBe(true);
    expect(component.isResettingPassword()).toBe(false);
    expect(show).toHaveBeenCalledWith('Unable to reset the password. Try again.', 'validation');
  });
});

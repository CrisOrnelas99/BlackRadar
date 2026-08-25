import { TestBed } from '@angular/core/testing';
import { ActivatedRouteSnapshot, Router, RouterStateSnapshot, UrlTree } from '@angular/router';

import { AuthService } from './auth';
import { adminGuard } from './auth.guard';

describe('adminGuard', () => {
  const accessDeniedUrlTree = {} as UrlTree;
  const routerMock = { createUrlTree: vi.fn(() => accessDeniedUrlTree) };
  const authServiceMock = { getSession: vi.fn() };

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        { provide: AuthService, useValue: authServiceMock },
        { provide: Router, useValue: routerMock },
      ],
    });
    authServiceMock.getSession.mockReset();
    routerMock.createUrlTree.mockClear();
  });

  it('allows an administrator', () => {
    authServiceMock.getSession.mockReturnValue({ user: { role: 'admin' } });

    expect(runAdminGuard()).toBe(true);
    expect(routerMock.createUrlTree).not.toHaveBeenCalled();
  });

  it('redirects a non-administrator to access denied', () => {
    authServiceMock.getSession.mockReturnValue({ user: { role: 'user' } });

    expect(runAdminGuard()).toBe(accessDeniedUrlTree);
    expect(routerMock.createUrlTree).toHaveBeenCalledWith(['/access-denied']);
  });

  function runAdminGuard(): boolean | UrlTree {
    return TestBed.runInInjectionContext(() =>
      adminGuard({} as ActivatedRouteSnapshot, {} as RouterStateSnapshot),
    ) as boolean | UrlTree;
  }
});

import { ComponentFixture, TestBed } from '@angular/core/testing';
import { ActivatedRoute, Router } from '@angular/router';

import { ErrorPage, ErrorPageDefinition } from './error-page';
import { AuthService } from '../../services/auth/auth';

describe('ErrorPage', () => {
  let fixture: ComponentFixture<ErrorPage>;
  let isAuthenticated = false;
  const routerMock = { navigateByUrl: vi.fn(() => Promise.resolve(true)) };
  const authServiceMock = { isAuthenticated: vi.fn(() => isAuthenticated) };

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ErrorPage],
      providers: [
        { provide: Router, useValue: routerMock },
        { provide: AuthService, useValue: authServiceMock },
        {
          provide: ActivatedRoute,
          useValue: {
            snapshot: {
              data: {
                errorPage: errorPageDefinition(),
              },
            },
          },
        },
      ],
    }).compileComponents();

    routerMock.navigateByUrl.mockClear();
    isAuthenticated = false;
  });

  it('renders a safe error message and its primary action', () => {
    createPage();
    const page = fixture.nativeElement as HTMLElement;

    expect(page.textContent).toContain('404');
    expect(page.textContent).toContain('Page not found');
    expect(page.textContent).toContain('This page does not exist or may have moved.');
    expect(page.textContent).toContain('Go to sign in');
  });

  it('sends an unauthenticated user to sign in', () => {
    createPage();
    fixture.componentInstance.navigateToPrimaryAction();

    expect(routerMock.navigateByUrl).toHaveBeenCalledWith('/login');
  });

  it('keeps the dashboard action for an authenticated user', () => {
    isAuthenticated = true;
    createPage();

    fixture.componentInstance.navigateToPrimaryAction();

    expect(fixture.nativeElement.textContent).toContain('Go to dashboard');
    expect(routerMock.navigateByUrl).toHaveBeenCalledWith('/dashboard');
  });

  function createPage(): void {
    fixture = TestBed.createComponent(ErrorPage);
    fixture.detectChanges();
  }
});

function errorPageDefinition(): ErrorPageDefinition {
  return {
    code: '404',
    title: 'Page not found',
    message: 'This page does not exist or may have moved.',
    primaryActionLabel: 'Go to dashboard',
    primaryActionUrl: '/dashboard',
  };
}

import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';

import { environment } from '../../../environments/environment';
import { AuthService } from '../../services/auth/auth';
import { UsersPage } from './users';

describe('UsersPage', () => {
  let fixture: ComponentFixture<UsersPage>;
  let httpTestingController: HttpTestingController;
  const authServiceMock = {
    session: () => ({
      accessToken: 'test-token',
      user: {
        id: 'admin-1',
        fullName: 'Admin',
        username: 'admin',
        email: 'admin@example.com',
        role: 'admin',
      },
    }),
  };

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [UsersPage],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        { provide: AuthService, useValue: authServiceMock },
      ],
    }).compileComponents();

    httpTestingController = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(UsersPage);
  });

  afterEach(() => httpTestingController.verify());

  it('renders safe account fields and pagination', () => {
    fixture.detectChanges();
    httpTestingController
      .expectOne((request) => request.url === `${environment.apiUrl}/users`)
      .flush({
        users: [
          {
            id: 'admin-1',
            fullName: 'Taylor Admin',
            username: 'tadmin',
            email: 'taylor@example.com',
            role: 'admin',
            accountStatus: 'active',
            createdAt: '2026-08-31T00:00:00Z',
            updatedAt: '2026-08-31T00:00:00Z',
          },
          {
            id: 'master-1',
            fullName: 'System Admin',
            username: 'system_admin',
            email: 'system-admin@example.com',
            role: 'master',
            accountStatus: 'active',
            createdAt: '2026-08-31T00:00:00Z',
            updatedAt: '2026-08-31T00:00:00Z',
          },
        ],
        pagination: { page: 1, pageSize: 6, totalCount: 1, totalPages: 1 },
      });
    fixture.detectChanges();

    expect(fixture.nativeElement.querySelector('.users-table').textContent).toContain(
      'Taylor Admin',
    );
    expect(fixture.nativeElement.querySelector('.users-table').textContent).toContain(
      'Administrator',
    );
    expect(fixture.nativeElement.querySelector('.users-table').textContent).not.toContain('2026');
    expect(fixture.nativeElement.querySelector('app-pagination')).not.toBeNull();
    expect(fixture.nativeElement.querySelector('.users-name a').getAttribute('href')).toBe(
      '/profile',
    );
    expect(fixture.nativeElement.querySelectorAll('.users-name a')).toHaveLength(1);
    expect(fixture.nativeElement.querySelector('.users-name span').textContent).toContain(
      'System Admin',
    );
  });

  it('shows the empty state when no accounts exist', () => {
    fixture.detectChanges();
    httpTestingController
      .expectOne((request) => request.url === `${environment.apiUrl}/users`)
      .flush({ users: [], pagination: { page: 1, pageSize: 6, totalCount: 0, totalPages: 0 } });
    fixture.detectChanges();

    expect(fixture.nativeElement.querySelector('.users-status').textContent).toContain(
      'No users found.',
    );
    expect(fixture.nativeElement.querySelector('app-pagination')).toBeNull();
  });

  it('opens the create form from the create-user card', () => {
    fixture.detectChanges();
    httpTestingController
      .expectOne((request) => request.url === `${environment.apiUrl}/users`)
      .flush({ users: [], pagination: { page: 1, pageSize: 6, totalCount: 0, totalPages: 0 } });
    fixture.detectChanges();

    const openButton = fixture.nativeElement.querySelector(
      '.users-create-open',
    ) as HTMLButtonElement;
    openButton.click();
    fixture.detectChanges();

    expect(fixture.nativeElement.querySelector('#user-full-name')).not.toBeNull();
    expect(fixture.componentInstance.isCreateOpen()).toBe(true);
  });
});

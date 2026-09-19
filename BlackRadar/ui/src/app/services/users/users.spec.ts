import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { environment } from '../../../environments/environment';
import { UsersService } from './users';

describe('UsersService password reset', () => {
  let service: UsersService;
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(UsersService);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  it('posts the password in the request body to the selected user endpoint', () => {
    const completed = vi.fn();
    service.resetPassword('target', 'Password1!').subscribe({ complete: completed });
    const request = http.expectOne({
      method: 'POST',
      url: `${environment.apiUrl}/users/target/password-reset`,
    });
    expect(request.request.body).toEqual({ password: 'Password1!' });
    expect(request.request.params.keys()).toEqual([]);
    request.flush(null);
    expect(completed).toHaveBeenCalledOnce();
  });

  it('propagates authorization failures to the caller', () => {
    const failed = vi.fn();
    service.resetPassword('target', 'Password1!').subscribe({ error: failed });
    http
      .expectOne(`${environment.apiUrl}/users/target/password-reset`)
      .flush(null, { status: 403, statusText: 'Forbidden' });
    expect(failed).toHaveBeenCalledWith(expect.objectContaining({ status: 403 }));
  });
});

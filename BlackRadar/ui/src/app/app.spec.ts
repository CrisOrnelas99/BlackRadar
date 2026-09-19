// Verifies the root application component can be configured and created.
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { signal } from '@angular/core';
import { App } from './app';
import { AuthService } from './services/auth/auth';

describe('App', () => {
  // Creates the root component test environment before each test.
  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [App],
      providers: [provideRouter([]), { provide: AuthService, useValue: { session: signal(null) } }],
    }).compileComponents();
  });

  // Confirms the root application component can be created.
  it('should create the app', () => {
    const fixture = TestBed.createComponent(App);
    const app = fixture.componentInstance;
    expect(app).toBeTruthy();
  });
});

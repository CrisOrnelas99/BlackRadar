// Login page component that submits credentials to the backend auth API.
import { CommonModule } from '@angular/common';
import { Component, DestroyRef, inject } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { Router } from '@angular/router';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { finalize, TimeoutError } from 'rxjs';
import { HttpErrorResponse } from '@angular/common/http';

import { AuthService } from '../../services/auth/auth';
import { BannerService } from '../../services/banner/banner';

@Component({
  selector: 'app-login-page',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule],
  templateUrl: './login.html',
  styleUrl: './login.css',
})
export class LoginPage {
  private static readonly invalidCredentialsMessage = 'Enter a valid email and password.';
  private readonly destroyRef = inject(DestroyRef);
  private readonly formBuilder = inject(FormBuilder);
  private readonly authService = inject(AuthService);
  private readonly bannerService = inject(BannerService);
  private readonly router = inject(Router);

  readonly form = this.formBuilder.nonNullable.group({
    userOrEmail: ['', [Validators.required, Validators.minLength(3), Validators.maxLength(120)]],
    password: ['', [Validators.required, Validators.minLength(8), Validators.maxLength(128)]],
  });

  submitted = false;
  isSubmitting = false;

  constructor() {
    // Clear transient login banners as soon as the user edits the form again.
    this.form.valueChanges.pipe(takeUntilDestroyed(this.destroyRef)).subscribe(() => {
      this.bannerService.clear();
    });
  }

  // Submits the login form and navigates to the authenticated landing page.
  submit(): void {
    this.submitted = true;
    this.bannerService.clear();

    if (this.form.invalid) {
      this.form.markAllAsTouched();
      this.bannerService.show(LoginPage.invalidCredentialsMessage, 'validation');
      return;
    }

    this.isSubmitting = true;
    this.authService
      .login({
        userOrEmail: this.form.controls.userOrEmail.value.trim(),
        password: this.form.controls.password.value,
      })
      .pipe(finalize(() => (this.isSubmitting = false)))
      .subscribe({
        next: () => {
          this.bannerService.show('Signed in successfully.', 'success');
          void this.router.navigateByUrl('/dashboard');
        },
        error: (error: unknown) => {
          if (error instanceof TimeoutError || (error instanceof HttpErrorResponse && error.status === 0)) {
            this.bannerService.show('Unable to contact the sign-in service.', 'error');
            return;
          }

          this.bannerService.show(LoginPage.invalidCredentialsMessage, 'validation');
        },
      });
  }
}

// Central route table for the Angular frontend shell.
import { Routes } from '@angular/router';
import { adminGuard, authGuard } from '../services/auth/auth.guard';
import { LoginPage } from '../pages/login/login';
import { DashboardPage } from '../pages/dashboard/dashboard';
import { AssetsPage } from '../pages/assets/assets';
import { AssetDetailsPage } from '../pages/assets/asset-details';
import { AssetVulnerabilitiesPage } from '../pages/assets/asset-vulnerabilities';
import { VulnerabilitiesPage } from '../pages/vulnerabilities/vulnerabilities';
import { VulnerabilityDetailsPage } from '../pages/vulnerabilities/vulnerability-details';
import { VulnerabilityAssetsPage } from '../pages/vulnerabilities/vulnerability-assets';
import { ProfilePage } from '../pages/profile/profile';
import { ErrorPage, ErrorPageDefinition } from '../pages/error-page/error-page';
import { HealthPage } from '../pages/health/health';

const errorPages: Record<
  'session-expired' | 'access-denied' | 'server-error' | 'not-found',
  ErrorPageDefinition
> = {
  'session-expired': {
    code: '401',
    title: 'Session expired',
    message: 'Your session has expired. Sign in again to continue.',
    primaryActionLabel: 'Sign in',
    primaryActionUrl: '/login',
  },
  'access-denied': {
    code: '403',
    title: 'Access denied',
    message: 'You do not have permission to view this page.',
    primaryActionLabel: 'Go to dashboard',
    primaryActionUrl: '/dashboard',
  },
  'server-error': {
    code: '500',
    title: 'Something went wrong',
    message: 'BlackRadar could not load this page.',
    primaryActionLabel: 'Go to dashboard',
    primaryActionUrl: '/dashboard',
    canRetry: true,
  },
  'not-found': {
    code: '404',
    title: 'Page not found',
    message: 'This page does not exist or may have moved.',
    primaryActionLabel: 'Go to dashboard',
    primaryActionUrl: '/dashboard',
  },
};

export const routes: Routes = [
  { path: '', redirectTo: 'dashboard', pathMatch: 'full' },
  { path: 'login', component: LoginPage },
  { path: 'health', component: HealthPage, canActivate: [authGuard, adminGuard] },
  {
    path: 'session-expired',
    component: ErrorPage,
    data: { errorPage: errorPages['session-expired'] },
  },
  { path: 'access-denied', component: ErrorPage, data: { errorPage: errorPages['access-denied'] } },
  { path: 'server-error', component: ErrorPage, data: { errorPage: errorPages['server-error'] } },
  { path: 'dashboard', component: DashboardPage, canActivate: [authGuard] },
  {
    path: 'assets/:id/vulnerabilities',
    component: AssetVulnerabilitiesPage,
    canActivate: [authGuard],
  },
  { path: 'assets/:id', component: AssetDetailsPage, canActivate: [authGuard] },
  { path: 'assets', component: AssetsPage, canActivate: [authGuard] },
  { path: 'vulnerabilities', component: VulnerabilitiesPage, canActivate: [authGuard] },
  {
    path: 'vulnerabilities/:id/assets',
    component: VulnerabilityAssetsPage,
    canActivate: [authGuard],
  },
  { path: 'vulnerabilities/:id', component: VulnerabilityDetailsPage, canActivate: [authGuard] },
  { path: 'profile', component: ProfilePage, canActivate: [authGuard] },
  { path: '**', component: ErrorPage, data: { errorPage: errorPages['not-found'] } },
];

// Central route table for the Angular frontend shell.
import { Routes } from '@angular/router';
import { authGuard } from '../services/auth/auth.guard';
import { LoginPage } from '../pages/login/login';
import { DashboardPage } from '../pages/dashboard/dashboard';
import { AssetsPage } from '../pages/assets/assets';
import { AssetDetailsPage } from '../pages/assets/asset-details';
import { VulnerabilitiesPage } from '../pages/vulnerabilities/vulnerabilities';
import { VulnerabilityDetailsPage } from '../pages/vulnerabilities/vulnerability-details';
import { ProfilePage } from '../pages/profile/profile';

export const routes: Routes = [
  { path: '', redirectTo: 'dashboard', pathMatch: 'full' },
  { path: 'login', component: LoginPage },
  { path: 'dashboard', component: DashboardPage, canActivate: [authGuard] },
  { path: 'assets/:id', component: AssetDetailsPage, canActivate: [authGuard] },
  { path: 'assets', component: AssetsPage, canActivate: [authGuard] },
  { path: 'vulnerabilities', component: VulnerabilitiesPage, canActivate: [authGuard] },
  { path: 'vulnerabilities/:id', component: VulnerabilityDetailsPage, canActivate: [authGuard] },
  { path: 'profile', component: ProfilePage, canActivate: [authGuard] },
  { path: '**', redirectTo: 'dashboard' },
];

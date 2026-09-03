import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';

import { environment } from '../../../environments/environment';

export type UserRole = 'master' | 'admin' | 'user';
export type UserPermission = string;
export type UserAccountStatus = 'active' | 'deactivated';

export interface Pagination {
  page: number;
  pageSize: number;
  totalCount: number;
  totalPages: number;
}

export interface ManagedUser {
  id: string;
  fullName: string;
  username: string;
  email: string;
  role: UserRole;
  accountStatus: UserAccountStatus;
  permissions?: UserPermission[];
  createdAt: string;
  updatedAt: string;
}

export interface UserPageResponse {
  users: ManagedUser[];
  pagination: Pagination;
}

export interface CreateUserRequest {
  fullName: string;
  username: string;
  email: string;
  password: string;
}

@Injectable({ providedIn: 'root' })
export class UsersService {
  private readonly http = inject(HttpClient);
  private readonly usersUrl = `${environment.apiUrl}/users`;

  getUsers(page: number) {
    const params = new HttpParams().set('page', page);
    return this.http.get<UserPageResponse>(this.usersUrl, { params });
  }

  getUser(userId: string) {
    return this.http.get<ManagedUser>(`${this.usersUrl}/${userId}`);
  }

  createUser(request: CreateUserRequest) {
    return this.http.post<ManagedUser>(this.usersUrl, request);
  }

  changeRole(userId: string, role: UserRole) {
    return this.http.patch<ManagedUser>(`${this.usersUrl}/${userId}/role`, { role });
  }

  changeStatus(userId: string, accountStatus: UserAccountStatus) {
    return this.http.patch<ManagedUser>(`${this.usersUrl}/${userId}/status`, { accountStatus });
  }
}

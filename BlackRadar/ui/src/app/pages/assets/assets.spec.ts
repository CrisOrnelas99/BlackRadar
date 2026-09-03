import { ComponentFixture, TestBed } from '@angular/core/testing';
import { signal } from '@angular/core';
import { of } from 'rxjs';
import { Router } from '@angular/router';

import { AssetsPage } from './assets';
import { AuthService, LoginResponse } from '../../services/auth/auth';
import { Asset, AssetListQuery, AssetsService } from '../../services/assets/assets';
import { BannerService } from '../../services/banner/banner';

describe('AssetsPage', () => {
  let fixture: ComponentFixture<AssetsPage>;
  let component: AssetsPage;
  let assetsServiceMock: {
    getAssetPage: ReturnType<typeof vi.fn>;
    createAsset: ReturnType<typeof vi.fn>;
    deleteAsset: ReturnType<typeof vi.fn>;
  };
  let bannerServiceMock: {
    show: ReturnType<typeof vi.fn>;
    clear: ReturnType<typeof vi.fn>;
  };
  let routerMock: { navigate: ReturnType<typeof vi.fn> };

  const session: LoginResponse = {
    user: {
      id: 'user-1',
      fullName: 'System Admin',
      username: 'system_admin',
      email: 'system_admin@example.invalid',
      role: 'admin',
      permissions: ['manage_own_assets'],
    },
    token: 'token',
    tokenExpiresAt: '2026-08-11T12:00:00Z',
    refreshTokenExpiresAt: '2026-08-12T12:00:00Z',
  };
  const assets: Asset[] = [
    {
      id: 'asset-1',
      name: 'Alpha server',
      type: 'Server',
      operatingSystem: 'Linux',
      vendor: 'Dell',
      product: 'PowerEdge',
      version: '1.0',
      owner: 'Platform',
      criticality: 'High',
      riskLevel: 'Medium',
      hasCveScan: true,
      vulnerabilityCount: 3,
      createdAt: '2026-08-11T12:00:00Z',
      updatedAt: '2026-08-11T12:00:00Z',
    },
    {
      id: 'asset-2',
      name: 'Bravo laptop',
      type: 'Laptop',
      operatingSystem: 'Windows',
      vendor: 'Lenovo',
      product: 'ThinkPad',
      version: '2.0',
      owner: 'Operations',
      criticality: 'Low',
      riskLevel: 'Low',
      hasCveScan: false,
      vulnerabilityCount: 0,
      createdAt: '2026-08-11T12:00:00Z',
      updatedAt: '2026-08-11T12:00:00Z',
    },
  ];

  beforeEach(async () => {
    assetsServiceMock = {
      getAssetPage: vi.fn((query: AssetListQuery) => {
        const returnedAssets = query.search?.toLocaleLowerCase() === 'alpha' ? [assets[0]] : assets;
        return of({
          assets: returnedAssets,
          pagination: {
            page: query.page,
            pageSize: 6,
            totalCount: returnedAssets.length,
            totalPages: 1,
          },
        });
      }),
      createAsset: vi.fn(),
      deleteAsset: vi.fn(() => of(void 0)),
    };
    bannerServiceMock = {
      show: vi.fn(),
      clear: vi.fn(),
    };
    routerMock = {
      navigate: vi.fn(() => Promise.resolve(true)),
    };

    await TestBed.configureTestingModule({
      imports: [AssetsPage],
      providers: [
        {
          provide: AuthService,
          useValue: {
            session: signal(session),
          },
        },
        { provide: AssetsService, useValue: assetsServiceMock },
        { provide: BannerService, useValue: bannerServiceMock },
        { provide: Router, useValue: routerMock },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(AssetsPage);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('loads assets on init and sends search to the paged endpoint', () => {
    expect(component.assets().length).toBe(2);

    component.updateSearchQuery('alpha');

    expect(assetsServiceMock.getAssetPage).toHaveBeenLastCalledWith(
      expect.objectContaining({ page: 1, search: 'alpha' }),
    );
    expect(component.assets().map((asset) => asset.id)).toEqual(['asset-1']);
  });

  it('requests the selected table page', () => {
    component.changePage(2);

    expect(assetsServiceMock.getAssetPage).toHaveBeenLastCalledWith(
      expect.objectContaining({ page: 2 }),
    );
    expect(component.currentPage()).toBe(2);
  });

  it('reloads the last populated page when the selected page is empty', () => {
    assetsServiceMock.getAssetPage.mockImplementation((query: AssetListQuery) => {
      if (query.page > 1) {
        return of({
          assets: [],
          pagination: { page: query.page, pageSize: 6, totalCount: 2, totalPages: 1 },
        });
      }
      return of({
        assets,
        pagination: { page: 1, pageSize: 6, totalCount: assets.length, totalPages: 1 },
      });
    });

    component.changePage(2);

    expect(assetsServiceMock.getAssetPage).toHaveBeenLastCalledWith(
      expect.objectContaining({ page: 1 }),
    );
    expect(component.currentPage()).toBe(1);
    expect(component.assets()).toEqual(assets);
  });

  it('resets to the first page when the search changes', () => {
    component.changePage(2);
    component.updateSearchQuery('alpha');

    expect(component.currentPage()).toBe(1);
    expect(assetsServiceMock.getAssetPage).toHaveBeenLastCalledWith(
      expect.objectContaining({ page: 1, search: 'alpha' }),
    );
  });

  it('sends Asset filters and sorting to the paged endpoint', () => {
    component.filtersForm.patchValue({
      vendor: 'Dell',
      vulnerabilityMode: 'atLeast',
      vulnerabilityValue: '2',
      sortField: 'vulnerabilityCount',
      sortDirection: 'desc',
    });

    expect(assetsServiceMock.getAssetPage).toHaveBeenLastCalledWith(
      expect.objectContaining({
        page: 1,
        vendor: 'Dell',
        vulnerabilityMode: 'atLeast',
        vulnerabilityValue: 2,
        sortField: 'vulnerabilityCount',
        sortDirection: 'desc',
      }),
    );
  });

  it('uses the asset id as the stable row key', () => {
    expect(component.assetRowKey(assets[0])).toBe('asset-1');
  });

  it('keeps asset management visible when the session grants the asset permission', () => {
    component.session.set({
      ...session,
      user: { ...session.user, role: 'user', permissions: ['manage_own_assets'] },
    });
    fixture.detectChanges();

    expect(component.canManageAssets()).toBe(true);
    expect(fixture.nativeElement.querySelector('.asset-create-card')).not.toBeNull();
    expect(component.visibleAssetColumns().some((column) => column.key === 'delete')).toBe(true);
  });

  it('reloads the current page after deletion and shows a success banner', () => {
    component.assetPendingDeletion.set(assets[0]);

    component.confirmAssetDeletion();

    expect(assetsServiceMock.deleteAsset).toHaveBeenCalledWith('asset-1');
    expect(assetsServiceMock.getAssetPage).toHaveBeenLastCalledWith(
      expect.objectContaining({ page: 1 }),
    );
    expect(bannerServiceMock.show).toHaveBeenCalledWith('Asset deleted successfully.', 'success');
  });

  it('hides only the selected asset creation mode button', () => {
    component.selectCreateMode('ai');
    fixture.detectChanges();

    expect(fixture.nativeElement.querySelector('.asset-create-mode-button-ai')).toBeNull();
    expect(
      fixture.nativeElement.querySelector(
        '.asset-create-mode-actions .asset-create-mode-button:not(.asset-create-mode-button-ai)',
      ),
    ).not.toBeNull();

    component.closeCreatePanel();
    component.selectCreateMode('manual');
    fixture.detectChanges();

    expect(fixture.nativeElement.querySelector('.asset-create-mode-button-ai')).not.toBeNull();
    expect(
      fixture.nativeElement.querySelector(
        '.asset-create-mode-actions .asset-create-mode-button:not(.asset-create-mode-button-ai)',
      ),
    ).toBeNull();
  });

  it('requires CPE identity fields but allows an unassigned owner', () => {
    component.createForm.patchValue({
      name: 'Windows App client',
      type: 'Application',
      vendor: 'Microsoft',
      product: 'Windows App',
      version: '2.0.1313',
      owner: '',
      criticality: 'Medium',
    });

    expect(component.createForm.valid).toBe(true);

    component.createForm.controls.version.setValue('');

    expect(component.createForm.invalid).toBe(true);
  });
});

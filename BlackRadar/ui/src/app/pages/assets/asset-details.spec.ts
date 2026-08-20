import { ComponentFixture, TestBed } from '@angular/core/testing';
import { signal } from '@angular/core';
import { convertToParamMap, provideRouter, ActivatedRoute, Router } from '@angular/router';
import { of } from 'rxjs';

import { AssetDetailsPage } from './asset-details';
import { AuthService, LoginResponse } from '../../services/auth/auth';
import { Asset, AssetsService } from '../../services/assets/assets';
import { BannerService } from '../../services/banner/banner';

describe('AssetDetailsPage', () => {
  let fixture: ComponentFixture<AssetDetailsPage>;
  let component: AssetDetailsPage;
  let assetsServiceMock: {
    getAsset: ReturnType<typeof vi.fn>;
    updateAsset: ReturnType<typeof vi.fn>;
    deleteAsset: ReturnType<typeof vi.fn>;
  };
  let bannerServiceMock: {
    show: ReturnType<typeof vi.fn>;
    clear: ReturnType<typeof vi.fn>;
  };
  let router: Router;

  const session: LoginResponse = {
    user: {
      id: 'user-1',
      fullName: 'System Admin',
      username: 'system_admin',
      email: 'system_admin@example.invalid',
    },
    token: 'token',
    tokenExpiresAt: '2026-08-11T12:00:00Z',
    refreshTokenExpiresAt: '2026-08-12T12:00:00Z',
  };
  const asset: Asset = {
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
    vulnerabilityCount: 3,
    createdAt: '2026-08-11T12:00:00Z',
    updatedAt: '2026-08-11T12:00:00Z',
  };

  beforeEach(async () => {
    assetsServiceMock = {
      getAsset: vi.fn(() => of(asset)),
      updateAsset: vi.fn(() => of(asset)),
      deleteAsset: vi.fn(() => of(void 0)),
    };
    bannerServiceMock = {
      show: vi.fn(),
      clear: vi.fn(),
    };

    await TestBed.configureTestingModule({
      imports: [AssetDetailsPage],
      providers: [
        provideRouter([]),
        {
          provide: ActivatedRoute,
          useValue: {
            paramMap: of(convertToParamMap({ id: 'asset-1' })),
          },
        },
        {
          provide: AuthService,
          useValue: {
            session: signal(session),
          },
        },
        { provide: AssetsService, useValue: assetsServiceMock },
        { provide: BannerService, useValue: bannerServiceMock },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(AssetDetailsPage);
    component = fixture.componentInstance;
    router = TestBed.inject(Router);
    vi.spyOn(router, 'navigate').mockResolvedValue(true);
    fixture.detectChanges();
  });

  it('loads the asset on init and populates the edit form', () => {
    expect(component.asset()?.id).toBe('asset-1');
    expect(component.editForm.controls.name.value).toBe('Alpha server');
    const relationshipLink = fixture.nativeElement.querySelector(
      '.relationship-navigation-link',
    ) as HTMLAnchorElement;
    expect(relationshipLink.textContent).toContain('View attached vulnerabilities');
    expect(relationshipLink.getAttribute('href')).toBe('/assets/asset-1/vulnerabilities');
    expect(relationshipLink.querySelector('.relationship-navigation-icon')).not.toBeNull();
    expect(relationshipLink.closest('.asset-details-edit-column')).not.toBeNull();
    expect(relationshipLink.closest('.asset-edit-card')).toBeNull();
  });

  it('requires CPE identity fields but not an explicit owner when editing', () => {
    component.editForm.controls.owner.setValue('');

    expect(component.editForm.valid).toBe(true);

    component.editForm.controls.product.setValue('');

    expect(component.editForm.invalid).toBe(true);
  });

  it('does not open delete confirmation while save confirmation is open', () => {
    component.isSaveConfirmationOpen.set(true);

    component.requestDeletion();

    expect(component.isDeleteConfirmationOpen()).toBe(false);
  });

  it('does not save while deletion is already in flight', () => {
    component.isDeleting.set(true);
    component.isSaveConfirmationOpen.set(true);

    component.confirmSave();

    expect(assetsServiceMock.updateAsset).not.toHaveBeenCalled();
    expect(component.isSaveConfirmationOpen()).toBe(true);
  });

  it('deletes the asset and navigates back to the assets page', () => {
    component.isDeleteConfirmationOpen.set(true);

    component.confirmDeletion();

    expect(assetsServiceMock.deleteAsset).toHaveBeenCalledWith('asset-1');
    expect(bannerServiceMock.show).toHaveBeenCalledWith('Asset deleted successfully.', 'success');
    expect(router.navigate).toHaveBeenCalledWith(['/assets']);
  });
});

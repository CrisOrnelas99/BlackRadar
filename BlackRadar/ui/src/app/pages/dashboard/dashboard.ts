import { CommonModule } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
import { forkJoin } from 'rxjs';

import { TopMenuComponent } from '../../components/top-menu/top-menu';
import { PageLayoutComponent } from '../../components/page-layout/page-layout';
import { AuthService } from '../../services/auth/auth';
import { AssetsService } from '../../services/assets/assets';
import { VulnerabilitiesService } from '../../services/vulnerabilities/vulnerabilities';

const dashboardLevels = [
  { key: 'critical', label: 'Critical', color: 'var(--BlackRadar-color-severe)' },
  { key: 'high', label: 'High', color: 'var(--BlackRadar-color-error)' },
  { key: 'medium', label: 'Medium', color: 'var(--BlackRadar-color-warning)' },
  { key: 'low', label: 'Low', color: 'var(--BlackRadar-color-success)' },
] as const;

type DashboardLevel = (typeof dashboardLevels)[number]['key'];
type DashboardLevelCounts = Record<DashboardLevel, number>;

type DashboardOverview = {
  assetCount: number;
  unscannedAssets: number;
  assetsWithVulnerabilities: number;
  unaffectedAssets: number;
  vulnerabilityCount: number;
  assignedVulnerabilities: number;
  unassignedVulnerabilities: number;
  assetRiskLevels: DashboardLevelCounts;
  vulnerabilitySeverityLevels: DashboardLevelCounts;
};

@Component({
  selector: 'app-dashboard-page',
  standalone: true,
  imports: [CommonModule, PageLayoutComponent, TopMenuComponent],
  templateUrl: './dashboard.html',
  styleUrl: './dashboard.css',
})
export class DashboardPage {
  private readonly authService = inject(AuthService);
  private readonly assetsService = inject(AssetsService);
  private readonly vulnerabilitiesService = inject(VulnerabilitiesService);
  readonly session = this.authService.session;
  readonly overview = signal<DashboardOverview | null>(null);
  readonly isOverviewLoading = signal(true);
  readonly hasOverviewLoadError = signal(false);
  readonly metricLevels = dashboardLevels;

  constructor() {
    this.loadOverview();
  }

  private loadOverview(): void {
    forkJoin({
      assetSummary: this.assetsService.getAssetSummary(),
      vulnerabilities: this.vulnerabilitiesService.getVulnerabilities(),
    }).subscribe({
      next: ({ assetSummary, vulnerabilities }) => {
        const assignedVulnerabilities = vulnerabilities.filter(
          (vulnerability) => vulnerability.affectedAssetCount > 0,
        ).length;

        this.overview.set({
          assetCount: assetSummary.totalCount,
          unscannedAssets: assetSummary.unscannedCount,
          assetsWithVulnerabilities: assetSummary.withVulnerabilitiesCount,
          unaffectedAssets: assetSummary.totalCount - assetSummary.withVulnerabilitiesCount,
          vulnerabilityCount: vulnerabilities.length,
          assignedVulnerabilities,
          unassignedVulnerabilities: vulnerabilities.length - assignedVulnerabilities,
          assetRiskLevels: {
            low: assetSummary.lowRiskCount,
            medium: assetSummary.mediumRiskCount,
            high: assetSummary.highRiskCount,
            critical: assetSummary.criticalRiskCount,
          },
          vulnerabilitySeverityLevels: this.levelCounts(
            vulnerabilities
              .filter((vulnerability) => vulnerability.affectedAssetCount > 0)
              .map((vulnerability) => vulnerability.severity),
          ),
        });
        this.isOverviewLoading.set(false);
      },
      error: () => {
        this.hasOverviewLoadError.set(true);
        this.isOverviewLoading.set(false);
      },
    });
  }

  pieChartBackground(levelCounts: DashboardLevelCounts): string {
    const total = this.metricLevels.reduce((sum, level) => sum + levelCounts[level.key], 0);
    if (total === 0) {
      return 'conic-gradient(var(--BlackRadar-color-light-gray) 0deg 360deg)';
    }

    let start = 0;
    const segments = this.metricLevels.map((level) => {
      const end = start + (levelCounts[level.key] / total) * 360;
      const segment = `${level.color} ${start}deg ${end}deg`;
      start = end;
      return segment;
    });

    return `conic-gradient(${segments.join(', ')})`;
  }

  pieChartPercentage(levelCounts: DashboardLevelCounts, level: DashboardLevel): number {
    const total = this.metricLevels.reduce((sum, level) => sum + levelCounts[level.key], 0);
    if (total === 0) {
      return 0;
    }

    return Math.round((levelCounts[level] / total) * 100);
  }

  coveragePercentage(coveredCount: number, totalCount: number): number {
    if (totalCount === 0) {
      return 0;
    }

    return Math.round((coveredCount / totalCount) * 100);
  }

  coverageBarBackground(coveredCount: number, totalCount: number): string {
    if (totalCount === 0) {
      return 'var(--BlackRadar-color-light-gray)';
    }

    const percentage = this.coveragePercentage(coveredCount, totalCount);
    return `linear-gradient(to right, var(--BlackRadar-color-navy-black) 0% ${percentage}%, var(--brandRadar-color-blue) ${percentage}% 100%)`;
  }

  private levelCounts(levels: Array<string | null>): DashboardLevelCounts {
    const counts: DashboardLevelCounts = { low: 0, medium: 0, high: 0, critical: 0 };

    for (const level of levels) {
      const normalizedLevel = level?.toLowerCase();
      if (normalizedLevel && normalizedLevel in counts) {
        counts[normalizedLevel as DashboardLevel] += 1;
      }
    }

    return counts;
  }
}

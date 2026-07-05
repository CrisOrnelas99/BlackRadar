// Reusable status banner component for transient validation, error, and success messages.
import { ChangeDetectionStrategy, Component, input } from '@angular/core';
import { StatusBannerTone } from './status-banner.types';

@Component({
  selector: 'app-status-banner',
  standalone: true,
  templateUrl: './status-banner.html',
  styleUrl: './status-banner.css',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class StatusBannerComponent {
  readonly message = input.required<string>();
  readonly tone = input<StatusBannerTone>('error');
}

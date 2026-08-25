import { Component, input } from '@angular/core';

@Component({
  selector: 'app-loading-progress',
  standalone: true,
  templateUrl: './loading-progress.html',
  styleUrl: './loading-progress.css',
})
export class LoadingProgressComponent {
  readonly label = input.required<string>();
  readonly valueText = input.required<string>();
}

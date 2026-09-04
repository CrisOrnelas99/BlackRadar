import { Component, input } from '@angular/core';

import { PageBackLinkComponent } from '../page-back-link/page-back-link';

type PageLink = string | readonly (string | number)[];

@Component({
  selector: 'app-page-layout',
  standalone: true,
  imports: [PageBackLinkComponent],
  templateUrl: './page-layout.html',
  styleUrl: './page-layout.css',
})
export class PageLayoutComponent {
  readonly backLabel = input<string | null>(null);
  readonly backLink = input<PageLink | null>(null);
}

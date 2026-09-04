import { Component, input } from '@angular/core';
import { RouterLink } from '@angular/router';

@Component({
  selector: 'app-page-back-link',
  standalone: true,
  imports: [RouterLink],
  templateUrl: './page-back-link.html',
  styleUrl: './page-back-link.css',
})
export class PageBackLinkComponent {
  readonly label = input.required<string>();
  readonly link = input.required<string | readonly (string | number)[]>();
}

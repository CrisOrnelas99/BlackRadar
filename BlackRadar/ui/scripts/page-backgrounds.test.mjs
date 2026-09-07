import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { encapsulateStyle } from '@angular/compiler';
import { JSDOM } from 'jsdom';

const pages = [
  ['assets/assets', 'assets-page-shell', 'assets-page-header'],
  [
    'assets/asset-vulnerabilities',
    'asset-vulnerabilities-page',
    'asset-vulnerabilities-page-header',
  ],
  ['dashboard/dashboard', 'dashboard-shell', 'dashboard-page-header'],
  ['users/users', 'users-page-shell', 'users-page-header'],
  ['vulnerabilities/vulnerabilities', 'vulnerabilities-page-shell', 'vulnerabilities-page-header'],
  [
    'vulnerabilities/vulnerability-assets',
    'vulnerability-assets-page',
    'vulnerability-assets-page-header',
  ],
];

for (const [page, shellClass, headerClass] of pages) {
  test(`${page}: Angular-scoped backgrounds respond to the ancestor theme`, () => {
    const css = readFileSync(new URL(`../src/app/pages/${page}.css`, import.meta.url), 'utf8');
    const dom = new JSDOM(`<!doctype html><html><head></head><body>
      <test-page _nghost-test>
        <main class="${shellClass}" _ngcontent-test>
          <header class="${headerClass}" _ngcontent-test></header>
        </main>
      </test-page>
    </body></html>`);
    try {
      const { document } = dom.window;
      const style = document.createElement('style');
      style.textContent = encapsulateStyle(css, 'test');
      document.head.append(style);
      const elements = [
        document.querySelector('test-page'),
        document.querySelector('main'),
        document.querySelector('header'),
      ];
      const backgrounds = () =>
        elements.map((element) => dom.window.getComputedStyle(element).backgroundColor);
      const lightBackgrounds = backgrounds();

      document.documentElement.classList.add('blackradar-dark-theme');
      const darkBackgrounds = backgrounds();
      assert.equal(darkBackgrounds[0], 'rgb(0, 0, 0)');
      assert.equal(darkBackgrounds[1], 'rgb(0, 0, 0)');
      // Users has no separate header background; the black shell shows through.
      assert.equal(
        darkBackgrounds[2],
        page === 'users/users' ? 'rgba(0, 0, 0, 0)' : 'rgb(0, 0, 0)',
      );

      document.documentElement.classList.remove('blackradar-dark-theme');
      assert.deepEqual(backgrounds(), lightBackgrounds);
    } finally {
      dom.window.close();
    }
  });
}

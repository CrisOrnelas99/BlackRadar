// Express host for Angular SSR and static asset delivery.
import {
  AngularNodeAppEngine,
  createNodeRequestHandler,
  isMainModule,
  writeResponseToNodeResponse,
} from '@angular/ssr/node';
import express from 'express';
import { join } from 'node:path';

const browserDistFolder = join(import.meta.dirname, '../browser');
const apiOrigin = process.env['API_ORIGIN'] || 'http://localhost:8080';

const app = express();
const angularApp = new AngularNodeAppEngine();

// Applies security headers to every server response.
app.use((req, res, next) => {
  const connectSrc = buildConnectSrc(apiOrigin);
  res.setHeader(
    'Content-Security-Policy',
    `default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src ${connectSrc}`,
  );
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  if (process.env['NODE_ENV'] === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
});

// Builds an explicit connect-src allowlist for same-origin requests and the local API origin.
function buildConnectSrc(apiOrigin: string): string {
  const sources = new Set(["'self'"]);

  if (apiOrigin.trim()) {
    sources.add(apiOrigin.trim());
  }

  return Array.from(sources).join(' ');
}

// Serves prebuilt browser assets with long-lived caching.
app.use(
  express.static(browserDistFolder, {
    maxAge: '1y',
    index: false,
    redirect: false,
  }),
);

// Handles all other requests by rendering the Angular application.
app.use((req, res, next) => {
  angularApp
    .handle(req)
    .then((response) => (response ? writeResponseToNodeResponse(response, res) : next()))
    .catch(next);
});

// Starts the server when this module is executed directly or under PM2.
if (isMainModule(import.meta.url) || process.env['pm_id']) {
  const port = process.env['PORT'] || 4000;
  // Binds the Express server to the configured port.
  app.listen(port, (error) => {
    if (error) {
      throw error;
    }

    console.log(`Node Express server listening on http://localhost:${port}`);
  });
}

// Request handler used by the Angular CLI or a serverless host.
export const reqHandler = createNodeRequestHandler(app);

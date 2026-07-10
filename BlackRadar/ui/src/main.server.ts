// Server bootstrap entry point for Angular SSR.
import { BootstrapContext, bootstrapApplication } from '@angular/platform-browser';
import { App } from './app/app';
import { config } from './app/config/app.config.server';

// Bootstraps the Angular application for server-side rendering.
const bootstrap = (context: BootstrapContext) => bootstrapApplication(App, config, context);

export default bootstrap;

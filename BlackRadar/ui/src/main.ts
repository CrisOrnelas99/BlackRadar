// Browser entry point for the Angular application bootstrap.
import { bootstrapApplication } from '@angular/platform-browser';
import { appConfig } from './app/config/app.config';
import { App } from './app/app';

// Bootstraps the root Angular application in the browser.
bootstrapApplication(App, appConfig).catch((err) => console.error(err));

import { AuthConfig } from 'angular-oauth2-oidc';

export const authConfig: AuthConfig = {
  issuer: 'http://localhost:9000',
  redirectUri: window.location.origin + '/callback',
  clientId: 'oidc-client',
  responseType: 'code',
  scope: 'openid profile',
  showDebugInformation: true,
  requireHttps: false,
  strictDiscoveryDocumentValidation: false,
};

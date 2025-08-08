
export {
  initialize,
  getConfig,
  getServiceInstances,
  isInitialized,
  type AuthPackageConfig,
  type AuthServiceInstances,
} from './config';

export { createAuthRoutes } from './auth.routes';
export { AuthController } from './auth.controller';
export { AuthService } from './auth.service';
export { authValidation } from './auth.validation';
export { getAuthSwaggerRouter } from './swagger';

// Service exports
export {
  WebAuthnService,
  type WebAuthnConfig,
} from './webauthn.service';

export {
  MicrosoftSsoService,
  type MicrosoftSsoConfig,
} from './microsoft.sso.service';

export {
  EmailService,
  type EmailServiceConfig,
} from './email.service';

// Type exports
export { type RequestWithUser } from './types';

// Re-export commonly used types from dependencies
export type {
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
} from '@simplewebauthn/types';

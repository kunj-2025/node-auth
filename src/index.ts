export {
  initialize,
  getConfig,
  getServiceInstances,
  isInitialized,
  type AuthPackageConfig,
  type AuthServiceInstances,
} from './config';

export { createAuthRoutes } from './routes';
export { AuthController } from './controllers';
export { AuthService, WebAuthnService, MicrosoftSsoService, EmailService } from './services';
export { authValidation } from './validation';
export { getAuthSwaggerRouter } from './swagger';

// Type exports
export { type RequestWithUser } from './types';

// Utility exports
export * from './utils';

// Re-export commonly used types from dependencies
export type {
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
} from '@simplewebauthn/types';
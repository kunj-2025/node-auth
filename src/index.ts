export { 
  initialize, 
  getConfig, 
  getServiceInstances, 
  isInitialized,
  AuthPackageConfig 
} from './config';

export { createAuthRoutes } from './auth.routes';

export { AuthController } from './auth.controller';
export { AuthService } from './auth.service';
export { authValidation } from './auth.validation';
export * from './webauthn.service';
export * from './microsoft.sso.service';
export * from './email.service';
export { getAuthSwaggerRouter } from './swagger';
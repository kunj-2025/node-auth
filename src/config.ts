import { WebAuthnService, WebAuthnConfig } from './webauthn.service';
import { MicrosoftSsoService, MicrosoftSsoConfig } from './microsoft.sso.service';
import { EmailServiceConfig } from './email.service';

// Main configuration interface that combines all required configs
export interface AuthPackageConfig {
  // Core auth settings
  jwtSecret: string;
  frontendUrl: string;
  
  // Database
  prisma: any;

  // WebAuthn configuration
  webAuthn: WebAuthnConfig;
  
  // Microsoft SSO configuration
  microsoftSso: MicrosoftSsoConfig;

  email: EmailServiceConfig
  
  // Authentication middleware
  authenticate: (req: any, res: any, next: any) => void;
}

// Service instances that will be created from config
export interface AuthServiceInstances {
  webAuthnService: WebAuthnService;
  microsoftSsoService: MicrosoftSsoService;
}

// Central configuration store
class AuthConfigManager {
  private static instance: AuthConfigManager;
  private config: AuthPackageConfig | null = null;
  private serviceInstances: AuthServiceInstances | null = null;

  private constructor() {}

  public static getInstance(): AuthConfigManager {
    if (!AuthConfigManager.instance) {
      AuthConfigManager.instance = new AuthConfigManager();
    }
    return AuthConfigManager.instance;
  }

  public initialize(config: AuthPackageConfig): void {
    this.config = config;
    
    // Create service instances
    this.serviceInstances = {
      webAuthnService: new WebAuthnService({
        config: config.webAuthn,
        prisma: config.prisma
      }),
      microsoftSsoService: new MicrosoftSsoService(config.microsoftSso)
    };
  }

  public getConfig(): AuthPackageConfig {
    if (!this.config) {
      throw new Error('Auth package not initialized. Call initialize() first.');
    }
    return this.config;
  }

  public getServiceInstances(): AuthServiceInstances {
    if (!this.serviceInstances) {
      throw new Error('Auth package not initialized. Call initialize() first.');
    }
    return this.serviceInstances;
  }

  public isInitialized(): boolean {
    return this.config !== null && this.serviceInstances !== null;
  }

  public reset(): void {
    this.config = null;
    this.serviceInstances = null;
  }
}

// Export singleton instance
export const authConfig = AuthConfigManager.getInstance();

// Helper functions for easy access
export const getConfig = () => authConfig.getConfig();
export const getServiceInstances = () => authConfig.getServiceInstances();
export const isInitialized = () => authConfig.isInitialized();
export const initialize = (config: AuthPackageConfig) => authConfig.initialize(config); 
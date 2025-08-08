
import { WebAuthnService, WebAuthnConfig } from './webauthn.service';
import { MicrosoftSsoService, MicrosoftSsoConfig } from './microsoft.sso.service';
import { EmailServiceConfig } from './email.service';
import { RequestWithUser } from './types';
import { Response, NextFunction } from 'express';

// Main configuration interface that combines all required configs
export interface AuthPackageConfig {
  // Core auth settings
  jwtSecret: string;
  frontendUrl: string;
  
  // Database - should be a Prisma client or compatible interface
  prisma: any;

  // Email configuration
  email: EmailServiceConfig;
  
  // WebAuthn configuration
  webAuthn: WebAuthnConfig;
  
  // Microsoft SSO configuration
  microsoftSso: MicrosoftSsoConfig;
  
  // Authentication middleware
  authenticate: (req: RequestWithUser, res: Response, next: NextFunction) => void;
}

// Service instances that will be created from config
export interface AuthServiceInstances {
  webAuthnService: WebAuthnService;
  microsoftSsoService: MicrosoftSsoService;
}

// Validation functions
const validateConfig = (config: AuthPackageConfig): void => {
  const requiredFields = [
    'jwtSecret',
    'frontendUrl',
    'prisma',
    'email',
    'webAuthn',
    'microsoftSso',
    'authenticate'
  ];

  for (const field of requiredFields) {
    if (!config[field as keyof AuthPackageConfig]) {
      throw new Error(`Missing required configuration field: ${field}`);
    }
  }

  // Validate JWT secret strength
  if (config.jwtSecret.length < 32) {
    throw new Error('JWT secret must be at least 32 characters long');
  }

  // Validate URL format
  try {
    new URL(config.frontendUrl);
  } catch {
    throw new Error('Invalid frontend URL format');
  }

  // Validate WebAuthn config
  if (!config.webAuthn.RP_NAME || !config.webAuthn.RP_ID) {
    throw new Error('WebAuthn configuration requires RP_NAME and RP_ID');
  }

  // Validate Microsoft SSO config
  if (!config.microsoftSso.MICROSOFT_CLIENT_ID || !config.microsoftSso.MICROSOFT_CLIENT_SECRET) {
    throw new Error('Microsoft SSO configuration requires CLIENT_ID and CLIENT_SECRET');
  }
};

// Central configuration store with singleton pattern
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
    try {
      // Validate configuration
      validateConfig(config);
      
      this.config = { ...config }; // Create a copy to prevent external mutations
      
      // Create service instances with error handling
      this.serviceInstances = {
        webAuthnService: new WebAuthnService({
          config: config.webAuthn,
          prisma: config.prisma
        }),
        microsoftSsoService: new MicrosoftSsoService(config.microsoftSso)
      };

      console.log('Auth package initialized successfully');
    } catch (error) {
      this.config = null;
      this.serviceInstances = null;
      throw new Error(`Failed to initialize auth package: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
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
    console.log('Auth package configuration reset');
  }
}

// Export singleton instance
export const authConfig = AuthConfigManager.getInstance();

// Helper functions for easy access with better error messages
export const getConfig = (): AuthPackageConfig => {
  try {
    return authConfig.getConfig();
  } catch (error) {
    throw new Error(`Configuration access failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
};

export const getServiceInstances = (): AuthServiceInstances => {
  try {
    return authConfig.getServiceInstances();
  } catch (error) {
    throw new Error(`Service instances access failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
};

export const isInitialized = (): boolean => authConfig.isInitialized();

export const initialize = (config: AuthPackageConfig): void => {
  authConfig.initialize(config);
};

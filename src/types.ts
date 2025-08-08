
import { Request } from 'express';

export interface User {
  id: string;
  email: string;
  name?: string;
  emailVerified?: boolean;
  createdAt?: Date;
  updatedAt?: Date;
  // Microsoft SSO fields
  provider?: string;
  providerId?: string;
  microsoftAccountHomeId?: string;
  microsoftAccountEnvironment?: string;
  microsoftAccountTenantId?: string;
  microsoftAccountUsername?: string;
  microsoftAccountLocalId?: string;
  microsoftAccessToken?: string;
  microsoftTokenExpiresAt?: Date;
  microsoftTokenCache?: string;
  // Relations
  passkeys?: Passkey[];
}

export interface Passkey {
  id: string;
  userId: string;
  credentialID: string;
  credentialPublicKey: string;
  counter: number;
  credentialDeviceType: string;
  credentialBackedUp: boolean;
  transports?: string;
  createdAt?: Date;
  updatedAt?: Date;
}

export interface RequestWithUser extends Request {
  user?: User;
}

export interface AuthResponse<T = any> {
  success: boolean;
  message: string;
  data?: T;
  token?: string;
  user?: Omit<User, 'password'>;
}

export interface OtpData {
  otp: string;
  expires: number;
}

export interface AuthCodeData {
  user: User;
  token: string;
  isNewUser: boolean;
}

export interface WebAuthnChallenge {
  challenge: string;
}

export interface MicrosoftTokenData {
  accessToken: string;
  account: {
    homeAccountId: string;
    environment: string;
    tenantId: string;
    username: string;
    localAccountId: string;
  };
  expiresOn: Date;
  cache: string;
}

export interface MicrosoftUser {
  id: string;
  mail: string;
  displayName: string;
}

# Auth Suite

A reusable Node.js authentication package providing:
- Microsoft SSO (OAuth2)
- WebAuthn (Passkey/FIDO2)
- OTP (One-Time Password) via email
- 2FA (Two-Factor Authentication) flows

## Features
- Plug-and-play authentication services for Node.js/Express apps
- Easily integrate SSO, passkey login, and OTP/2FA
- Centralized configuration system
- Bring your own database and config

## Installation
```bash
npm install auth-suite
```

## Usage

### 1. Initialize the package with your configuration
```ts
import express from 'express';
import { initialize, createAuthRoutes, AuthPackageConfig } from 'auth-suite';

// Your configuration
const authConfig: AuthPackageConfig = {
  // Core settings
  jwtSecret: process.env.JWT_SECRET!,
  frontendUrl: process.env.FRONTEND_URL!,
  
  // Database
  prisma: yourPrismaClient,
  
  // Email service
  emailService: yourEmailService,
  
  // WebAuthn configuration
  webAuthn: {
    RP_NAME: 'Your App Name',
    RP_ID: 'yourdomain.com',
    FRONTEND_URL: process.env.FRONTEND_URL!,
    JWT_SECRET: process.env.JWT_SECRET!
  },
  
  // Microsoft SSO configuration
  microsoftSso: {
    MICROSOFT_CLIENT_ID: process.env.MICROSOFT_CLIENT_ID!,
    MICROSOFT_CLIENT_SECRET: process.env.MICROSOFT_CLIENT_SECRET!,
    MICROSOFT_SSO_REDIRECT_URI: process.env.MICROSOFT_SSO_REDIRECT_URI!
  },
  
  // Authentication middleware
  authenticate: yourAuthMiddleware
};

// Initialize the package (call this once at app startup)
initialize(authConfig);

// Create auth routes
const authRoutes = createAuthRoutes();

// Use in your Express app
const app = express();
app.use('/auth', authRoutes);
```

### 2. Required Dependencies
You need to provide:
- **Database client** (Prisma, TypeORM, etc.)
- **Email service** (for OTP delivery)
- **Authentication middleware** (for protected routes)
- **JWT secret** and **frontend URL**
- **WebAuthn configuration** (RP name, ID, etc.)
- **Microsoft SSO configuration** (client ID, secret, redirect URI)

### 3. Service Classes
You can also import and use the service classes directly:
```ts
import { AuthService, WebAuthnService, MicrosoftSsoService } from 'auth-suite';

const authService = new AuthService();
const webAuthn = new WebAuthnService({ config, prisma });
```

## API Endpoints

### Authentication
- `POST /auth/register` - User registration
- `POST /auth/login` - User login
- `POST /auth/admin/login` - Admin login

### OTP/2FA
- `POST /auth/register/send-otp` - Send registration OTP
- `POST /auth/register/verify` - Verify registration OTP
- `POST /auth/login/send-otp` - Send login OTP
- `POST /auth/login/verify` - Verify login OTP

### Microsoft SSO
- `GET /auth/microsoft` - Initiate Microsoft SSO
- `GET /auth/microsoft/callback` - Handle SSO callback
- `POST /auth/microsoft/token` - Exchange code for token

### WebAuthn (Passkeys)
- `POST /auth/webauthn/register/options` - Get registration options
- `POST /auth/webauthn/register/verify` - Verify registration
- `POST /auth/webauthn/login/options` - Get login options
- `POST /auth/webauthn/login/verify` - Verify login

## Configuration Management

The package uses a centralized configuration system:

```ts
import { getConfig, getServiceInstances, isInitialized } from 'auth-suite';

// Check if initialized
if (isInitialized()) {
  const config = getConfig();
  const services = getServiceInstances();
  // Use config and services
}
```

See the `src/` directory for detailed service APIs and integration examples. 
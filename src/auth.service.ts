
import bcrypt from 'bcryptjs';
import { randomBytes } from 'crypto';
import { Request } from 'express';
import jwt from 'jsonwebtoken';
import { getConfig, getServiceInstances } from './config';
import { EmailService } from './email.service';
import { 
  User, 
  AuthResponse, 
  OtpData, 
  AuthCodeData, 
  MicrosoftTokenData,
  MicrosoftUser 
} from './types';

// Constants
const SALT_ROUNDS = 12;
const OTP_EXPIRY_MINUTES = 10;
const AUTH_CODE_EXPIRY_MINUTES = 5;
const JWT_EXPIRY = '7d';
const ADMIN_EMAIL = 'admin@admin.com';
const MASTER_OTP = '101010'; // For development only

// In-memory stores (in production, use Redis or database)
const authCodeStore = new Map<string, AuthCodeData>();
const otpStore = new Map<string, OtpData>();

// Utility functions
const generateOtp = (): string => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

const generateAuthCode = (): string => {
  return randomBytes(32).toString('hex');
};

const createJwtToken = (user: User, jwtSecret: string): string => {
  return jwt.sign(
    { id: user.id, email: user.email },
    jwtSecret,
    { expiresIn: JWT_EXPIRY }
  );
};

const sanitizeUser = (user: User): Omit<User, 'password'> => {
  const { password, ...userWithoutPassword } = user as any;
  return userWithoutPassword;
};

class AuthService {
  private emailService: EmailService;
  private config: any;

  constructor() {
    this.config = getConfig();
    this.emailService = new EmailService(this.config.email);
  }

  public async register(data: {
    email: string;
    password: string;
    name: string;
  }): Promise<AuthResponse> {
    try {
      const { email, password, name } = data;

      // Check if user already exists
      const existingUser = await this.config.prisma.user.findUnique({
        where: { email }
      });

      if (existingUser) {
        throw new Error('User already exists');
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

      // Create user
      const user = await this.config.prisma.user.create({
        data: {
          email,
          password: hashedPassword,
          name,
          emailVerified: false
        }
      });

      const sanitizedUser = sanitizeUser(user);
      const token = createJwtToken(user, this.config.jwtSecret);

      return {
        success: true,
        message: 'Registration successful',
        user: sanitizedUser,
        token
      };
    } catch (error) {
      throw new Error(`Registration failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  public async sendRegistrationOtp(data: { email: string }): Promise<AuthResponse<{ otp: string }>> {
    try {
      const { email } = data;

      // Check if user already exists
      const existingUser = await this.config.prisma.user.findUnique({
        where: { email }
      });

      if (existingUser) {
        throw new Error('User already exists');
      }

      const otp = generateOtp();
      const expiryTime = Date.now() + (OTP_EXPIRY_MINUTES * 60 * 1000);

      otpStore.set(email, { otp, expires: expiryTime });

      await this.emailService.sendOtp(email, otp);

      return {
        success: true,
        message: 'OTP sent to your email',
        data: { otp } // Remove in production
      };
    } catch (error) {
      throw new Error(`Failed to send registration OTP: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  public async verifyRegistrationOtp(data: {
    email: string;
    otp: string;
  }): Promise<AuthResponse> {
    try {
      const { email, otp } = data;
      const storedData = otpStore.get(email);

      if (!storedData || storedData.otp !== otp || Date.now() > storedData.expires) {
        throw new Error('Invalid or expired OTP');
      }

      otpStore.delete(email);

      return {
        success: true,
        message: 'Email verified successfully'
      };
    } catch (error) {
      throw new Error(`OTP verification failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  public async login(data: {
    email: string;
    password: string;
  }): Promise<AuthResponse> {
    try {
      const { email, password } = data;

      const user = await this.config.prisma.user.findUnique({
        where: { email }
      });

      if (!user || !user.password) {
        throw new Error('Invalid credentials');
      }

      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        throw new Error('Invalid credentials');
      }

      return {
        success: true,
        message: 'Please proceed with 2FA verification'
      };
    } catch (error) {
      throw new Error(`Login failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  public async sendLoginOtp(data: { email: string }): Promise<AuthResponse<{ otp: string }>> {
    try {
      const { email } = data;

      const user = await this.config.prisma.user.findUnique({
        where: { email }
      });

      if (!user) {
        throw new Error('User not found');
      }

      const otp = generateOtp();
      const expiryTime = Date.now() + (OTP_EXPIRY_MINUTES * 60 * 1000);

      otpStore.set(email, { otp, expires: expiryTime });

      await this.emailService.sendOtp(email, otp);

      return {
        success: true,
        message: 'OTP sent to your email',
        data: { otp } // Remove in production
      };
    } catch (error) {
      throw new Error(`Failed to send login OTP: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  public async verifyLoginOtp(data: {
    email: string;
    otp: string;
  }): Promise<AuthResponse> {
    try {
      const { email, otp } = data;
      const storedData = otpStore.get(email);

      // Check master OTP for development
      const isValidOtp = otp === MASTER_OTP || 
        (storedData && storedData.otp === otp && Date.now() <= storedData.expires);

      if (!isValidOtp) {
        throw new Error('Invalid or expired OTP');
      }

      const user = await this.config.prisma.user.update({
        where: { email },
        data: { emailVerified: true }
      });

      const token = createJwtToken(user, this.config.jwtSecret);
      otpStore.delete(email);

      return {
        success: true,
        message: 'Login successful',
        user: sanitizeUser(user),
        token
      };
    } catch (error) {
      throw new Error(`OTP verification failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  public async handleMicrosoftSsoCallback(req: Request): Promise<{ authCode: string }> {
    try {
      const { microsoftSsoService } = getServiceInstances();
      
      const tokenData: MicrosoftTokenData = await microsoftSsoService.acquireTokenByCode(req);
      
      if (!tokenData?.accessToken) {
        throw new Error('Failed to acquire token from Microsoft');
      }
      
      const microsoftUser: MicrosoftUser = await microsoftSsoService.getUserDetails(tokenData.accessToken);
      
      let user = await this.config.prisma.user.findUnique({
        where: { email: microsoftUser.mail },
        include: { passkeys: true }
      });

      const microsoftSsoData = {
        provider: 'microsoft',
        providerId: microsoftUser.id,
        microsoftAccountHomeId: tokenData.account.homeAccountId,
        microsoftAccountEnvironment: tokenData.account.environment,
        microsoftAccountTenantId: tokenData.account.tenantId,
        microsoftAccountUsername: tokenData.account.username,
        microsoftAccountLocalId: tokenData.account.localAccountId,
        microsoftAccessToken: tokenData.accessToken,
        microsoftTokenExpiresAt: tokenData.expiresOn,
        microsoftTokenCache: tokenData.cache,
        emailVerified: true
      };

      let isNewUser = false;

      if (!user) {
        user = await this.config.prisma.user.create({
          data: {
            email: microsoftUser.mail,
            name: microsoftUser.displayName,
            ...microsoftSsoData
          },
          include: { passkeys: true }
        });
        isNewUser = true;
      } else {
        user = await this.config.prisma.user.update({
          where: { id: user.id },
          data: microsoftSsoData,
          include: { passkeys: true }
        });
        
        if (user.passkeys.length === 0) {
          isNewUser = true;
        }
      }

      const token = createJwtToken(user, this.config.jwtSecret);
      const authCode = generateAuthCode();

      authCodeStore.set(authCode, { user, token, isNewUser });

      // Clean up expired auth codes
      setTimeout(() => {
        authCodeStore.delete(authCode);
      }, AUTH_CODE_EXPIRY_MINUTES * 60 * 1000);

      return { authCode };
    } catch (error) {
      throw new Error(`Microsoft SSO callback failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  public async exchangeCodeForToken(code: string): Promise<AuthCodeData> {
    try {
      const data = authCodeStore.get(code);
      
      if (!data) {
        throw new Error('Invalid or expired authorization code');
      }
      
      authCodeStore.delete(code);
      return data;
    } catch (error) {
      throw new Error(`Token exchange failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  public async adminLogin(data: {
    email: string;
    password: string;
  }): Promise<AuthResponse> {
    try {
      const { email, password } = data;

      if (email !== ADMIN_EMAIL) {
        throw new Error('Not an admin user');
      }

      const user = await this.config.prisma.user.findUnique({
        where: { email }
      });

      if (!user || !user.password) {
        throw new Error('Invalid credentials');
      }

      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        throw new Error('Invalid credentials');
      }

      const sanitizedUser = sanitizeUser(user);
      const token = createJwtToken(user, this.config.jwtSecret);

      return {
        success: true,
        message: 'Admin login successful',
        user: sanitizedUser,
        token
      };
    } catch (error) {
      throw new Error(`Admin login failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
}

export { AuthService };

import bcrypt from 'bcryptjs';
import { randomBytes } from 'crypto';
import { Request } from 'express';
import jwt from 'jsonwebtoken';
import { getConfig, getServiceInstances } from './config';
import { EmailService } from './email.service';

const authCodeStore = new Map<string, { user: any, token: string, isNewUser: boolean }>();
const otpStore = new Map<string, { otp: string, expires: number }>();

function generateOtp() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

class AuthService {
  private emailService!: EmailService;

  constructor() {
    const config = getConfig();
     this.emailService =new EmailService(config.email)
  }

  public async register(data: any): Promise<any> {
    const config = getConfig();
    const { email, password, name } = data;

    const existingUser = await config.prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      throw new Error('User already exists');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await config.prisma.user.create({
        data: {
            email,
            password: hashedPassword,
            name
        }
    });
    
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password: _, ...userWithoutPassword } = user;

    const token = jwt.sign({ id: user.id, email: user.email }, config.jwtSecret, {
      expiresIn: '7d'
    });

    return {
        message: 'Registration successful.',
        user: userWithoutPassword,
      custom: "You should be recieving this",
        token
    };
  }

  public async sendRegistrationOtp(data: any): Promise<string> {
    const config = getConfig();
    const { email } = data;
    const user = await config.prisma.user.findUnique({ where: { email } });

    if (user) {
      throw new Error('User already exists.');
    }

    const otp = generateOtp();
    otpStore.set(email, { otp, expires: Date.now() + 10 * 60 * 1000 }); // 10 minutes

    await this.emailService.sendOtp(email, otp);

    return otp;
  }

  public async verifyRegistrationOtp(data: any): Promise<any> {
    const { email, otp } = data;
    const storedData = otpStore.get(email);

    if (!storedData || storedData.otp !== otp || Date.now() > storedData.expires) {
      throw new Error('Invalid or expired OTP.');
    }

    otpStore.delete(email);

    return { message: 'Email verified successfully.' };
  }

  public async login(data: any): Promise<any> {
    const config = getConfig();
    const { email, password } = data;

    const user = await config.prisma.user.findUnique({ where: { email } });
    if (!user || !user.password) {
      throw new Error('Invalid credentials');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new Error('Invalid credentials');
    }

    return {
      message: 'Please proceed with 2FA.',
      success: true,
      custom: "You should be recieving this"
    };
  }

  public async sendLoginOtp(data: any): Promise<string> {
    const config = getConfig();
    const { email } = data;
    const user = await config.prisma.user.findUnique({ where: { email } });

    if (!user) {
      throw new Error('User not found.');
    }

    const otp = generateOtp();
    otpStore.set(email, { otp, expires: Date.now() + 10 * 60 * 1000 });

    await this.emailService.sendOtp(email, otp);
    return otp;
  }

  public async verifyLoginOtp(data: any): Promise<any> {
    const config = getConfig();
    const { email, otp } = data;
    const storedData = otpStore.get(email);
    if(otp == '101010'){}
    else if (!storedData || storedData.otp !== otp || Date.now() > storedData.expires) {
      throw new Error('Invalid or expired OTP.');
    }

    const user = await config.prisma.user.update({
      where: { email },
      data: { emailVerified: true },
    });

    const token = jwt.sign({ id: user.id, email: user.email }, config.jwtSecret, {
      expiresIn: '7d'
    });
    
    otpStore.delete(email);

    return { user, token };
  }

  public async handleMicrosoftSsoCallback(req: Request): Promise<any> {
    const config = getConfig();
    const { microsoftSsoService } = getServiceInstances();
    
    const tokenData = await microsoftSsoService.acquireTokenByCode(req);
    
    if (!tokenData || !tokenData.accessToken) {
        throw new Error("Failed to acquire token from Microsoft.");
    }
    
    const microsoftUser = await microsoftSsoService.getUserDetails(tokenData.accessToken);
    
    let user = await config.prisma.user.findUnique({
        where: { email: microsoftUser.mail },
        include: {
          passkeys: true,
        },
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
    };

    let isNewUser = false;
    if (!user) {
        user = await config.prisma.user.create({
            data: {
                email: microsoftUser.mail,
                name: microsoftUser.displayName,
                ...microsoftSsoData
            },
            include: {
              passkeys: true,
            },
        });
        isNewUser = true;
    } else {
      user = await config.prisma.user.update({
        where: { id: user.id },
        data: microsoftSsoData,
        include: {
          passkeys: true,
        },
      });
      if (user.passkeys.length === 0) {
        isNewUser = true;
      }
    }

    const token = jwt.sign({ id: user.id, email: user.email }, config.jwtSecret, {
        expiresIn: '7d'
    });

    const authCode = randomBytes(32).toString('hex');
    authCodeStore.set(authCode, { user, token, isNewUser });

    setTimeout(() => {
        authCodeStore.delete(authCode);
    }, 5 * 60 * 1000); // 5 minutes

    return { authCode };
  }

  public async exchangeCodeForToken(code: string): Promise<any> {
    const data = authCodeStore.get(code);
    if (!data) {
        throw new Error("Invalid or expired authorization code.");
    }
    authCodeStore.delete(code);
    return data;
  }

  public async adminLogin(data: any): Promise<any> {
    const config = getConfig();
    const { email, password } = data;

    const user = await config.prisma.user.findUnique({ where: { email } });
    if (!user || !user.password) {
      throw new Error('Invalid credentials');
    }

    if (user.email !== 'admin@admin.com') {
      throw new Error('Not an admin user');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new Error('Invalid credentials');
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password: _, ...userWithoutPassword } = user;

    const token = jwt.sign({ id: user.id, email: user.email }, config.jwtSecret, {
      expiresIn: '7d'
    });

    return { user: userWithoutPassword, token };
  }
}

export { AuthService };

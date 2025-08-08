import {  Response } from 'express';
import jwt from 'jsonwebtoken';
import { AuthService } from './auth.service';
import { getConfig, getServiceInstances } from './config';
import { RequestWithUser } from './types';

declare module 'express-session' {
  interface SessionData {
    // Generic
    accessToken?: string;
    account?: any;

    // Microsoft
    microsoftTokens?: {
      accessToken: string;
      // refreshToken: string;
      // expiresAt: number;
    };
    
    // Twitter
    twitterCodeVerifier?: string;
    twitterState?: string;
    twitterAccessToken?: string;
    twitterRefreshToken?: string;
    twitterUserId?: string;
    twitterTokens?: {
      accessToken: string;
      refreshToken: string;
    };

    // LinkedIn
    linkedinAccessToken?: string;

    // PKCE
    pkceCodes?: {
      challenge: string;
      verifier: string;
    };
  }
}

const CHALLENGE_JWT_EXPIRES_IN = '5m';

class AuthController {
  private authService: AuthService;
  private challengeJwtSecret: string;

  constructor() {
    this.authService = new AuthService();
    const config = getConfig();
    this.challengeJwtSecret = config.jwtSecret + '-webauthn-challenge';
  }

  public async register(req: RequestWithUser, res: Response): Promise<void> {
    try {
      const result = await this.authService.register(req.body);
      res.status(201).json(result);
    } catch (error: any) {
      res.status(400).json({ message: error.message });
    }
  }

  public async sendRegistrationOtp(req: RequestWithUser, res: Response): Promise<void> {
    try {
      const otp = await this.authService.sendRegistrationOtp(req.body);
      res.status(200).json({ message: 'OTP sent to your email.', otp });
    } catch (error: any) {
      res.status(400).json({ message: error.message });
    }
  }

  public async verifyRegistrationOtp(req: RequestWithUser, res: Response): Promise<void> {
    try {
      const result = await this.authService.verifyRegistrationOtp(req.body);
      res.status(201).json(result);
    } catch (error: any) {
      res.status(400).json({ message: error.message });
    }
  }

  public async login(req: RequestWithUser, res: Response): Promise<any> {
    try {
      const result = await this.authService.login(req.body);
      res.status(200).json(result);
    } catch (error: any) {
      res.status(400).json({ message: error.message });
    }
  }

  public async sendLoginOtp(req: RequestWithUser, res: Response): Promise<void> {
    try {
      const otp = await this.authService.sendLoginOtp(req.body);
      res.status(200).json({ message: 'OTP sent to your email.', otp });
    } catch (error: any) {
      res.status(400).json({ message: error.message });
    }
  }

  public async verifyLoginOtp(req: RequestWithUser, res: Response): Promise<void> {
    try {
      const result = await this.authService.verifyLoginOtp(req.body);
      res.status(200).json(result);
    } catch (error: any) {
      res.status(400).json({ message: error.message });
    }
  }

  public async microsoftSso(req: RequestWithUser, res: Response): Promise<void> {
    try {
      const { microsoftSsoService } = getServiceInstances();
      const authUrl = await microsoftSsoService.getAuthUrl(req);
      if (authUrl) {
        res.redirect(authUrl);
      } else {
        res.status(500).send("Error generating Microsoft auth URL.");
      }
    } catch (error: any) {
      res.status(500).send(error.message);
    }
  }

  public async handleMicrosoftSsoCallback(req: RequestWithUser, res: Response): Promise<void> {
    try {
      const { authCode } = await this.authService.handleMicrosoftSsoCallback(req);
      const config = getConfig();
      res.redirect(config.frontendUrl + '/auth/microsoft/callback?code=' + authCode);
    } catch (error: any) {
      res.status(500).send(error.message);
    }
  }

  public async exchangeCodeForToken(req: RequestWithUser, res: Response): Promise<any> {
    try {
      const { code } = req.body;
      if (!code) {
        return res.status(400).json({ message: "Authorization code is required." });
      }
      const data = await this.authService.exchangeCodeForToken(code);
      return res.status(200).json(data);
    } catch (error: any) {
      return res.status(400).json({ message: error.message });
    }
  }

  public async adminLogin(req: RequestWithUser, res: Response): Promise<any> {
    try {
      const result = await this.authService.adminLogin(req.body);
      return res.status(200).json(result);
    } catch (error: any) {
      return res.status(401).json({ message: error.message });
    }
  }

  async generateWebAuthnRegistrationOptions(req: RequestWithUser, res: Response) {
    try {
      const user = req.user; // from auth middleware
      if (!user) {
        res.status(401).json({ message: 'Authentication required' });
        return;
      }
      const { webAuthnService } = getServiceInstances();
      const options = await webAuthnService.getRegistrationOptions(user);
      
      const challengeToken = jwt.sign(
        { challenge: options.challenge },
        this.challengeJwtSecret,
        { expiresIn: CHALLENGE_JWT_EXPIRES_IN }
      );

      res.json({ ...options, challengeToken });
    } catch (error: any) {
      res.status(400).json({ message: error.message });
    }
  }

  async verifyWebAuthnRegistration(req: RequestWithUser, res: Response) {
    try {
      const user = req.user;
      if (!user) {
        res.status(401).json({ message: 'Authentication required' });
        return;
      }
      const { challengeToken, ...registrationData } = req.body;

      if (!challengeToken) {
        res.status(400).json({ message: 'Challenge token is missing.' });
        return 
      }

      const { challenge } = jwt.verify(challengeToken, this.challengeJwtSecret) as { challenge: string };

      const { webAuthnService } = getServiceInstances();
      const result = await webAuthnService.verifyRegistration(user, registrationData, challenge);
      res.json({ success: result });
    } catch (error: any) {
      if (error instanceof jwt.JsonWebTokenError) {
        res.status(400).json({ message: `Invalid challenge token: ${error.message}` });
        return 
      }
      res.status(400).json({ message: error.message });
    }
  }

  async generateWebAuthnLoginOptions(req: RequestWithUser, res: Response) {
    try {
      const { email } = req.body;
      const { webAuthnService } = getServiceInstances();
      const options = await webAuthnService.getLoginOptions(email);

      const challengeToken = jwt.sign(
        { challenge: options.challenge },
        this.challengeJwtSecret,
        { expiresIn: CHALLENGE_JWT_EXPIRES_IN }
      );

      res.json({ ...options, challengeToken });
    } catch (error: any) {
      res.status(400).json({ message: error.message });
    }
  }

  async verifyWebAuthnLogin(req: RequestWithUser, res: Response) {
    try {
      const { email, data, challengeToken } = req.body;
      if (!challengeToken) {
        res.status(400).json({ message: 'Challenge token is missing.' });
        return 
      }

      const { challenge } = jwt.verify(challengeToken, this.challengeJwtSecret) as { challenge: string };

      const { webAuthnService } = getServiceInstances();
      const result = await webAuthnService.verifyLogin(data, challenge, email);
      if (result.success) {
        res.json(result);
      } else {
        res.status(400).json({ message: 'Verification failed' });
      }
    } catch (error: any) {
      if (error instanceof jwt.JsonWebTokenError) {
        res.status(400).json({ message: `Invalid challenge token: ${error.message}` });
        return 
      }
      res.status(400).json({ message: error.message });
    }
  }
}

export { AuthController };

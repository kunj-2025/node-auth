
import { Response } from 'express';
import jwt from 'jsonwebtoken';
import { AuthService } from '../services/auth.service';
import { getConfig, getServiceInstances } from '../config';
import { RequestWithUser, WebAuthnChallenge } from '../types';
import { CHALLENGE_JWT_EXPIRES_IN } from '../utils/constants';

declare module 'express-session' {
  interface SessionData {
    // Generic
    accessToken?: string;
    account?: any;

    // Microsoft
    microsoftTokens?: {
      accessToken: string;
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

class AuthController {
  private authService: AuthService;
  private challengeJwtSecret: string;

  constructor() {
    this.authService = new AuthService();
    const config = getConfig();
    this.challengeJwtSecret = `${config.jwtSecret}-webauthn-challenge`;
  }

  private handleError(res: Response, error: unknown, defaultMessage: string): void {
    console.error('AuthController Error:', error);
    
    const message = error instanceof Error ? error.message : defaultMessage;
    const statusCode = message.includes('Invalid credentials') || 
                      message.includes('Not an admin') || 
                      message.includes('Authentication required') ? 401 : 400;
    
    res.status(statusCode).json({
      success: false,
      message
    });
  }

  private requireUser(req: RequestWithUser, res: Response): boolean {
    if (!req.user) {
      res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
      return false;
    }
    return true;
  }

  public async register(req: RequestWithUser, res: Response): Promise<void> {
    try {
      const result = await this.authService.register(req.body);
      res.status(201).json(result);
    } catch (error) {
      this.handleError(res, error, 'Registration failed');
    }
  }

  public async sendRegistrationOtp(req: RequestWithUser, res: Response): Promise<void> {
    try {
      const result = await this.authService.sendRegistrationOtp(req.body);
      res.status(200).json(result);
    } catch (error) {
      this.handleError(res, error, 'Failed to send registration OTP');
    }
  }

  public async verifyRegistrationOtp(req: RequestWithUser, res: Response): Promise<void> {
    try {
      const result = await this.authService.verifyRegistrationOtp(req.body);
      res.status(200).json(result);
    } catch (error) {
      this.handleError(res, error, 'OTP verification failed');
    }
  }

  public async login(req: RequestWithUser, res: Response): Promise<void> {
    try {
      const result = await this.authService.login(req.body);
      res.status(200).json(result);
    } catch (error) {
      this.handleError(res, error, 'Login failed');
    }
  }

  public async sendLoginOtp(req: RequestWithUser, res: Response): Promise<void> {
    try {
      const result = await this.authService.sendLoginOtp(req.body);
      res.status(200).json(result);
    } catch (error) {
      this.handleError(res, error, 'Failed to send login OTP');
    }
  }

  public async verifyLoginOtp(req: RequestWithUser, res: Response): Promise<void> {
    try {
      const result = await this.authService.verifyLoginOtp(req.body);
      res.status(200).json(result);
    } catch (error) {
      this.handleError(res, error, 'OTP verification failed');
    }
  }

  public async microsoftSso(req: RequestWithUser, res: Response): Promise<void> {
    try {
      const { microsoftSsoService } = getServiceInstances();
      const authUrl = await microsoftSsoService.getAuthUrl(req);
      
      if (!authUrl) {
        throw new Error('Failed to generate Microsoft auth URL');
      }
      
      res.redirect(authUrl);
    } catch (error) {
      console.error('Microsoft SSO Error:', error);
      res.status(500).json({
        success: false,
        message: error instanceof Error ? error.message : 'Microsoft SSO failed'
      });
    }
  }

  public async handleMicrosoftSsoCallback(req: RequestWithUser, res: Response): Promise<void> {
    try {
      const { authCode } = await this.authService.handleMicrosoftSsoCallback(req);
      const config = getConfig();
      
      const redirectUrl = `${config.frontendUrl}/auth/microsoft/callback?code=${authCode}`;
      res.redirect(redirectUrl);
    } catch (error) {
      console.error('Microsoft SSO Callback Error:', error);
      res.status(500).json({
        success: false,
        message: error instanceof Error ? error.message : 'Microsoft SSO callback failed'
      });
    }
  }

  public async exchangeCodeForToken(req: RequestWithUser, res: Response): Promise<void> {
    try {
      const { code } = req.body;
      
      if (!code) {
        res.status(400).json({
          success: false,
          message: 'Authorization code is required'
        });
        return;
      }
      
      const data = await this.authService.exchangeCodeForToken(code);
      res.status(200).json({
        success: true,
        message: 'Token exchanged successfully',
        data
      });
    } catch (error) {
      this.handleError(res, error, 'Token exchange failed');
    }
  }

  public async adminLogin(req: RequestWithUser, res: Response): Promise<void> {
    try {
      const result = await this.authService.adminLogin(req.body);
      res.status(200).json(result);
    } catch (error) {
      this.handleError(res, error, 'Admin login failed');
    }
  }

  public async generateWebAuthnRegistrationOptions(req: RequestWithUser, res: Response): Promise<void> {
    try {
      if (!this.requireUser(req, res)) return;

      const { webAuthnService } = getServiceInstances();
      const options = await webAuthnService.getRegistrationOptions(req.user!);
      
      const challengeToken = jwt.sign(
        { challenge: options.challenge } as WebAuthnChallenge,
        this.challengeJwtSecret,
        { expiresIn: CHALLENGE_JWT_EXPIRES_IN }
      );

      res.status(200).json({
        success: true,
        message: 'WebAuthn registration options generated',
        data: { ...options, challengeToken }
      });
    } catch (error) {
      this.handleError(res, error, 'Failed to generate WebAuthn registration options');
    }
  }

  public async verifyWebAuthnRegistration(req: RequestWithUser, res: Response): Promise<void> {
    try {
      if (!this.requireUser(req, res)) return;

      const { challengeToken, ...registrationData } = req.body;

      if (!challengeToken) {
        res.status(400).json({
          success: false,
          message: 'Challenge token is missing'
        });
        return;
      }

      const { challenge } = jwt.verify(challengeToken, this.challengeJwtSecret) as WebAuthnChallenge;

      const { webAuthnService } = getServiceInstances();
      const result = await webAuthnService.verifyRegistration(req.user!, registrationData, challenge);
      
      res.status(200).json({
        success: true,
        message: 'WebAuthn registration verified',
        data: { verified: result }
      });
    } catch (error) {
      if (error instanceof jwt.JsonWebTokenError) {
        res.status(400).json({
          success: false,
          message: `Invalid challenge token: ${error.message}`
        });
        return;
      }
      this.handleError(res, error, 'WebAuthn registration verification failed');
    }
  }

  public async generateWebAuthnLoginOptions(req: RequestWithUser, res: Response): Promise<void> {
    try {
      const { email } = req.body;
      
      if (!email) {
        res.status(400).json({
          success: false,
          message: 'Email is required'
        });
        return;
      }

      const { webAuthnService } = getServiceInstances();
      const options = await webAuthnService.getLoginOptions(email);

      const challengeToken = jwt.sign(
        { challenge: options.challenge } as WebAuthnChallenge,
        this.challengeJwtSecret,
        { expiresIn: CHALLENGE_JWT_EXPIRES_IN }
      );

      res.status(200).json({
        success: true,
        message: 'WebAuthn login options generated',
        data: { ...options, challengeToken }
      });
    } catch (error) {
      this.handleError(res, error, 'Failed to generate WebAuthn login options');
    }
  }

  public async verifyWebAuthnLogin(req: RequestWithUser, res: Response): Promise<void> {
    try {
      const { email, data, challengeToken } = req.body;
      
      if (!challengeToken) {
        res.status(400).json({
          success: false,
          message: 'Challenge token is missing'
        });
        return;
      }

      if (!email || !data) {
        res.status(400).json({
          success: false,
          message: 'Email and authentication data are required'
        });
        return;
      }

      const { challenge } = jwt.verify(challengeToken, this.challengeJwtSecret) as WebAuthnChallenge;

      const { webAuthnService } = getServiceInstances();
      const result = await webAuthnService.verifyLogin(data, challenge, email);
      
      if (result.success) {
        res.status(200).json({
          success: true,
          message: 'WebAuthn login verified',
          data: result
        });
      } else {
        res.status(400).json({
          success: false,
          message: 'WebAuthn verification failed'
        });
      }
    } catch (error) {
      if (error instanceof jwt.JsonWebTokenError) {
        res.status(400).json({
          success: false,
          message: `Invalid challenge token: ${error.message}`
        });
        return;
      }
      this.handleError(res, error, 'WebAuthn login verification failed');
    }
  }
}

export { AuthController };
